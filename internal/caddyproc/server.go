package caddyproc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/ssw-cloud/v2naive/internal/conf"
	"github.com/ssw-cloud/v2naive/internal/limiter"
	panel "github.com/ssw-cloud/v2naive/internal/panel"
)

type Server struct {
	node       *panel.NodeInfo
	runtime    conf.RuntimeConfig
	adminAddr  string
	authAddr   string
	configPath string
	workDir    string

	mu         sync.Mutex
	cmd        *exec.Cmd
	done       chan error
	authLn     net.Listener
	authServer *http.Server

	usersMu sync.RWMutex
	users   map[string]panel.UserInfo

	statsMu sync.RWMutex
	stats   map[string]*trafficCounter
	online  map[string]map[string]int
	limiter *limiter.Limiter
}

func New(node *panel.NodeInfo, users []panel.UserInfo, alive map[int]int, runtime conf.RuntimeConfig) *Server {
	adminPort := runtime.AdminPortBase + node.Id
	workDir := filepath.Join(runtime.WorkingDir, fmt.Sprintf("node-%d", node.Id))
	server := &Server{
		node:       node,
		runtime:    runtime,
		adminAddr:  "127.0.0.1:" + strconv.Itoa(adminPort),
		configPath: filepath.Join(workDir, "Caddyfile"),
		workDir:    workDir,
		users:      make(map[string]panel.UserInfo, len(users)),
		stats:      make(map[string]*trafficCounter, len(users)),
		online:     make(map[string]map[string]int),
		limiter:    limiter.New(users, alive),
	}
	server.replaceUsers(users)
	return server
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd != nil {
		return nil
	}
	if strings.TrimSpace(s.runtime.CaddyPath) == "" {
		return fmt.Errorf("caddy path is empty")
	}
	if _, err := os.Stat(s.runtime.CaddyPath); err != nil {
		return fmt.Errorf("stat caddy binary failed: %w", err)
	}
	if err := os.MkdirAll(s.workDir, 0755); err != nil {
		return fmt.Errorf("create work dir failed: %w", err)
	}
	if err := s.writeCoverSite(); err != nil {
		return fmt.Errorf("write cover site failed: %w", err)
	}
	if err := os.WriteFile(s.configPath, s.renderConfig(), 0644); err != nil {
		return fmt.Errorf("write caddyfile failed: %w", err)
	}
	if err := s.startAuthServerLocked(); err != nil {
		return fmt.Errorf("start auth server failed: %w", err)
	}

	cmd := exec.Command(s.runtime.CaddyPath, "run", "--config", s.configPath, "--adapter", "caddyfile")
	cmd.Dir = s.workDir
	cmd.Env = append(
		os.Environ(),
		"V2NAIVE_AUTH_URL=http://"+s.authAddr+"/authorize",
		"V2NAIVE_RELEASE_URL=http://"+s.authAddr+"/release",
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.stopAuthServerLocked()
		return fmt.Errorf("get caddy stdout pipe failed: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		s.stopAuthServerLocked()
		return fmt.Errorf("get caddy stderr pipe failed: %w", err)
	}
	if err := cmd.Start(); err != nil {
		s.stopAuthServerLocked()
		return fmt.Errorf("start caddy failed: %w", err)
	}

	done := make(chan error, 1)
	go s.consumeOutput(stdout, false)
	go s.consumeOutput(stderr, true)
	go func() {
		done <- cmd.Wait()
	}()

	s.cmd = cmd
	s.done = done

	if err := s.waitReady(); err != nil {
		_ = s.stopLocked()
		return err
	}

	log.WithFields(log.Fields{
		"node_id":    s.node.Id,
		"admin_addr": s.adminAddr,
		"addr":       fmt.Sprintf("%s:%d", s.node.ListenIP, s.node.ServerPort),
	}).Info("naive caddy runtime started")
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopLocked()
}

func (s *Server) stopLocked() error {
	if s.cmd == nil {
		return nil
	}

	proc := s.cmd.Process
	done := s.done
	s.cmd = nil
	s.done = nil

	if proc == nil {
		s.stopAuthServerLocked()
		return nil
	}

	_ = proc.Signal(syscall.SIGTERM)
	select {
	case <-done:
		s.stopAuthServerLocked()
		return nil
	case <-time.After(5 * time.Second):
		_ = proc.Kill()
		<-done
		s.stopAuthServerLocked()
		return nil
	}
}

func (s *Server) SetAliveList(alive map[int]int) {
	s.limiter.SetAliveList(alive)
}

func (s *Server) UpdateUsers(added, deleted, modified, full []panel.UserInfo) {
	if full != nil {
		s.replaceUsers(full)
	} else {
		s.applyUserDelta(added, deleted, modified)
	}
	s.limiter.UpdateUsers(added, deleted, modified)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd == nil {
		return
	}
	if err := s.writeCoverSite(); err != nil {
		log.WithError(err).Error("write cover site failed")
		return
	}
	if err := os.WriteFile(s.configPath, s.renderConfig(), 0644); err != nil {
		log.WithError(err).Error("rewrite caddyfile failed")
		return
	}
	reloadCmd := exec.Command(s.runtime.CaddyPath, "reload", "--config", s.configPath, "--adapter", "caddyfile", "--address", "http://"+s.adminAddr)
	reloadCmd.Dir = s.workDir
	output, err := reloadCmd.CombinedOutput()
	if err != nil {
		log.WithFields(log.Fields{
			"err":    err,
			"output": string(output),
		}).Error("reload caddy failed")
		return
	}
	log.WithField("node_id", s.node.Id).Info("reloaded naive caddy runtime")
}

func (s *Server) GetUserTrafficSlice(minTraffic int) []panel.UserTraffic {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()
	traffic := make([]panel.UserTraffic, 0, len(s.stats))
	for _, counter := range s.stats {
		if snapshot, ok := counter.snapshotIfAbove(minTraffic); ok {
			traffic = append(traffic, snapshot)
		}
	}
	return traffic
}

func (s *Server) GetOnlineDevice() []panel.OnlineUser {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()
	devices := make([]panel.OnlineUser, 0)
	for uuid, ipMap := range s.online {
		user := s.userByUUID(uuid)
		if user.Id == 0 {
			continue
		}
		for ip, count := range ipMap {
			if count > 0 {
				devices = append(devices, panel.OnlineUser{
					UID: user.Id,
					IP:  ip,
				})
			}
		}
	}
	return devices
}

func (s *Server) waitReady() error {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	adminURL := "http://" + s.adminAddr + "/config/"

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-s.done:
			replacement := make(chan error, 1)
			replacement <- err
			s.done = replacement
			if err == nil {
				return fmt.Errorf("caddy exited before becoming ready")
			}
			return fmt.Errorf("caddy exited early: %w", err)
		default:
		}

		resp, err := client.Get(adminURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	return fmt.Errorf("caddy admin endpoint did not become ready: %s", s.adminAddr)
}

func (s *Server) renderConfig() []byte {
	var buf bytes.Buffer

	buf.WriteString("{\n")
	buf.WriteString("  admin " + s.adminAddr + "\n")
	buf.WriteString("  auto_https disable_redirects\n")
	buf.WriteString("  order forward_proxy first\n")
	buf.WriteString("}\n\n")

	addresses := append([]string{":" + strconv.Itoa(s.node.ServerPort)}, collectHosts(s.node)...)
	buf.WriteString(strings.Join(addresses, ", ") + " {\n")
	if s.node.ListenIP != "" {
		buf.WriteString("  bind " + s.node.ListenIP + "\n")
	}
	buf.WriteString("  tls " + quote(s.node.CertInfo.CertFile) + " " + quote(s.node.CertInfo.KeyFile) + "\n")
	buf.WriteString("  forward_proxy {\n")
	users := s.userSnapshot()
	sort.Slice(users, func(i, j int) bool {
		return users[i].Uuid < users[j].Uuid
	})
	if len(users) == 0 {
		buf.WriteString("    basic_auth " + quote("__disabled__") + " " + quote("__disabled__") + "\n")
	}
	for _, user := range users {
		buf.WriteString("    basic_auth " + quote(user.Uuid) + " " + quote(user.Uuid) + "\n")
	}
	buf.WriteString("    probe_resistance\n")
	buf.WriteString("    hide_ip\n")
	buf.WriteString("    hide_via\n")
	buf.WriteString("    acl {\n")
	buf.WriteString("      allow all\n")
	buf.WriteString("    }\n")
	buf.WriteString("  }\n")
	buf.WriteString("  root * " + quote(s.coverDir()) + "\n")
	buf.WriteString("  file_server\n")
	buf.WriteString("}\n")

	return buf.Bytes()
}

func (s *Server) writeCoverSite() error {
	dir := s.coverDir()
	files := coverSiteFiles(s.node)
	for relativePath, content := range files {
		fullPath := filepath.Join(dir, relativePath)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) coverDir() string {
	return filepath.Join(s.workDir, "cover")
}

func coverSiteFiles(node *panel.NodeInfo) map[string]string {
	label := coverRegionLabel(node.Host)
	host := strings.TrimSpace(node.Host)
	if host == "" {
		host = "edge.sswnat.com"
	}
	statusUpdatedAt := time.Now().UTC().Format("2006-01-02 15:04 UTC")
	pageData := map[string]string{
		"{{TITLE}}":        "SSW Edge",
		"{{REGION_LABEL}}": label,
		"{{HOSTNAME}}":     host,
		"{{UPDATED_AT}}":   statusUpdatedAt,
	}
	return map[string]string{
		"index.html":  applyCoverTemplate(coverIndexHTML, pageData),
		"status.html": applyCoverTemplate(coverStatusHTML, pageData),
		"docs.html":   applyCoverTemplate(coverDocsHTML, pageData),
		"styles.css":  coverStylesCSS,
	}
}

func coverRegionLabel(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	switch {
	case strings.HasPrefix(host, "hk."):
		return "Hong Kong Edge"
	case strings.HasPrefix(host, "jp."):
		return "Japan Edge"
	case strings.HasPrefix(host, "sg."):
		return "Singapore Edge"
	case strings.HasPrefix(host, "us."):
		return "United States Edge"
	default:
		return "Global Edge"
	}
}

func applyCoverTemplate(template string, replacements map[string]string) string {
	for key, value := range replacements {
		template = strings.ReplaceAll(template, key, value)
	}
	return template
}

const coverStylesCSS = `:root {
  color-scheme: light;
  --bg: #f4f7fb;
  --panel: #ffffff;
  --muted: #607086;
  --text: #122033;
  --line: #d9e2ec;
  --accent: #1f6feb;
  --accent-soft: rgba(31, 111, 235, 0.12);
  --good: #157347;
}

* {
  box-sizing: border-box;
}

html, body {
  margin: 0;
  padding: 0;
  background: linear-gradient(180deg, #f8fbff 0%, var(--bg) 100%);
  color: var(--text);
  font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

a {
  color: inherit;
  text-decoration: none;
}

body {
  min-height: 100vh;
}

.shell {
  width: min(1120px, calc(100% - 40px));
  margin: 0 auto;
}

.site-header {
  padding: 24px 0 12px;
}

.header-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 14px;
  min-width: 0;
}

.brand-mark {
  width: 42px;
  height: 42px;
  border-radius: 10px;
  display: grid;
  place-items: center;
  background: linear-gradient(135deg, #0f5bd8 0%, #3b82f6 100%);
  color: #fff;
  font-size: 15px;
  font-weight: 700;
}

.brand-copy {
  min-width: 0;
}

.brand-copy strong,
.brand-copy span {
  display: block;
}

.brand-copy strong {
  font-size: 17px;
  font-weight: 600;
}

.brand-copy span {
  color: var(--muted);
  font-size: 13px;
  margin-top: 2px;
}

.nav {
  display: flex;
  gap: 18px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.nav a {
  color: var(--muted);
  font-size: 14px;
}

.nav a.active,
.nav a:hover {
  color: var(--text);
}

.hero {
  padding: 28px 0 36px;
}

.hero-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.2fr) minmax(280px, 0.8fr);
  gap: 22px;
}

.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  box-shadow: 0 8px 30px rgba(16, 24, 40, 0.04);
}

.hero-copy {
  padding: 34px;
}

.eyebrow {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  font-weight: 600;
  color: var(--accent);
  background: var(--accent-soft);
  border-radius: 999px;
  padding: 8px 12px;
}

.hero h1 {
  margin: 18px 0 14px;
  font-size: clamp(34px, 4vw, 52px);
  line-height: 1.04;
  font-weight: 650;
}

.hero p {
  margin: 0;
  color: var(--muted);
  font-size: 16px;
  line-height: 1.75;
  max-width: 60ch;
}

.metrics {
  margin-top: 28px;
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.metric {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 16px 18px;
}

.metric strong,
.metric span {
  display: block;
}

.metric strong {
  font-size: 24px;
  font-weight: 650;
}

.metric span {
  margin-top: 5px;
  color: var(--muted);
  font-size: 13px;
}

.hero-side {
  padding: 28px;
}

.side-title {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
}

.side-copy {
  margin: 10px 0 0;
  color: var(--muted);
  font-size: 14px;
  line-height: 1.7;
}

.status-list {
  margin: 22px 0 0;
  padding: 0;
  list-style: none;
  display: grid;
  gap: 12px;
}

.status-item {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 14px 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
}

.status-item strong,
.status-item span {
  display: block;
}

.status-item strong {
  font-size: 14px;
  font-weight: 600;
}

.status-item span {
  color: var(--muted);
  font-size: 12px;
  margin-top: 3px;
}

.pill {
  border-radius: 999px;
  padding: 7px 11px;
  font-size: 12px;
  font-weight: 600;
}

.pill.good {
  color: var(--good);
  background: rgba(21, 115, 71, 0.12);
}

.sections {
  padding-bottom: 48px;
}

.section-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
}

.section-card {
  padding: 22px;
}

.section-card h2 {
  margin: 0 0 10px;
  font-size: 18px;
}

.section-card p {
  margin: 0;
  color: var(--muted);
  font-size: 14px;
  line-height: 1.75;
}

.section-card ul {
  margin: 16px 0 0;
  padding-left: 18px;
  color: var(--muted);
  font-size: 14px;
  line-height: 1.75;
}

.page {
  padding: 24px 0 56px;
}

.page-hero {
  padding: 28px 30px;
  margin-bottom: 18px;
}

.page-hero h1 {
  margin: 0 0 10px;
  font-size: 30px;
}

.page-hero p {
  margin: 0;
  color: var(--muted);
  font-size: 15px;
  line-height: 1.75;
}

.status-table,
.docs-grid {
  display: grid;
  gap: 16px;
}

.status-row,
.doc-card {
  padding: 20px 22px;
}

.status-row {
  display: grid;
  grid-template-columns: minmax(0, 1.2fr) minmax(120px, 0.7fr) minmax(160px, 0.8fr);
  gap: 14px;
  align-items: center;
}

.status-row strong,
.status-row span {
  display: block;
}

.status-row strong {
  font-size: 15px;
  font-weight: 600;
}

.status-row span {
  color: var(--muted);
  font-size: 13px;
  margin-top: 4px;
}

.doc-card h2 {
  margin: 0 0 10px;
  font-size: 18px;
}

.doc-card p {
  margin: 0;
  color: var(--muted);
  font-size: 14px;
  line-height: 1.75;
}

.doc-card code {
  display: block;
  margin-top: 14px;
  padding: 14px 16px;
  border-radius: 8px;
  border: 1px solid var(--line);
  background: #f7f9fc;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 13px;
  color: #334155;
  white-space: pre-wrap;
  word-break: break-word;
}

.footer {
  padding: 22px 0 36px;
  color: var(--muted);
  font-size: 13px;
}

.footer-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  flex-wrap: wrap;
}

@media (max-width: 960px) {
  .hero-grid,
  .section-grid {
    grid-template-columns: 1fr;
  }

  .status-row {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 640px) {
  .shell {
    width: min(100% - 24px, 1120px);
  }

  .header-row,
  .metrics {
    grid-template-columns: 1fr;
  }

  .hero-copy,
  .hero-side,
  .page-hero,
  .section-card,
  .status-row,
  .doc-card {
    padding: 20px;
  }

  .metrics {
    display: grid;
  }
}`

const coverIndexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{TITLE}}</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <header class="site-header">
    <div class="shell header-row">
      <div class="brand">
        <div class="brand-mark">SE</div>
        <div class="brand-copy">
          <strong>SSW Edge</strong>
          <span>{{REGION_LABEL}}</span>
        </div>
      </div>
      <nav class="nav">
        <a class="active" href="/">Overview</a>
        <a href="/status.html">Status</a>
        <a href="/docs.html">Docs</a>
      </nav>
    </div>
  </header>

  <main class="hero">
    <div class="shell hero-grid">
      <section class="panel hero-copy">
        <div class="eyebrow">Regional edge access</div>
        <h1>Fast ingress for multi-region transport and API delivery.</h1>
        <p>
          {{HOSTNAME}} is part of the SSW Edge network, a regional ingress layer built for
          low-latency transport, resilient session handoff, and stable access across distributed
          points of presence.
        </p>
        <div class="metrics">
          <div class="metric">
            <strong>4</strong>
            <span>regional edge zones</span>
          </div>
          <div class="metric">
            <strong>99.95%</strong>
            <span>network availability target</span>
          </div>
          <div class="metric">
            <strong>24x7</strong>
            <span>traffic and health monitoring</span>
          </div>
        </div>
      </section>

      <aside class="panel hero-side">
        <h2 class="side-title">Current ingress profile</h2>
        <p class="side-copy">
          This edge hostname is currently serving the {{REGION_LABEL}} region and participating in
          cross-region ingress balancing for the wider SSW Edge fabric.
        </p>
        <ul class="status-list">
          <li class="status-item">
            <div>
              <strong>{{REGION_LABEL}}</strong>
              <span>primary regional ingress</span>
            </div>
            <span class="pill good">Operational</span>
          </li>
          <li class="status-item">
            <div>
              <strong>Protocol stack</strong>
              <span>HTTP, TLS, edge transport</span>
            </div>
            <span class="pill good">Healthy</span>
          </li>
          <li class="status-item">
            <div>
              <strong>Routing profile</strong>
              <span>multi-entry SNI dispatch enabled</span>
            </div>
            <span class="pill good">Stable</span>
          </li>
        </ul>
      </aside>
    </div>
  </main>

  <section class="sections">
    <div class="shell section-grid">
      <article class="panel section-card">
        <h2>Edge routing</h2>
        <p>
          Regional hostnames are announced through separate ingress entries and routed by SNI to
          the appropriate backend handling plane.
        </p>
      </article>
      <article class="panel section-card">
        <h2>Transport continuity</h2>
        <p>
          Session handling is optimized for consistent behavior across regional front doors, even
          when user traffic enters through different geographic access points.
        </p>
      </article>
      <article class="panel section-card">
        <h2>Operational visibility</h2>
        <p>
          Edge availability, ingress health, and transport telemetry are monitored continuously with
          region-aware reporting.
        </p>
      </article>
    </div>
  </section>

  <footer class="footer">
    <div class="shell footer-row">
      <span>SSW Edge</span>
      <span>{{HOSTNAME}}</span>
    </div>
  </footer>
</body>
</html>`

const coverStatusHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SSW Edge Status</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <header class="site-header">
    <div class="shell header-row">
      <div class="brand">
        <div class="brand-mark">SE</div>
        <div class="brand-copy">
          <strong>SSW Edge</strong>
          <span>{{REGION_LABEL}}</span>
        </div>
      </div>
      <nav class="nav">
        <a href="/">Overview</a>
        <a class="active" href="/status.html">Status</a>
        <a href="/docs.html">Docs</a>
      </nav>
    </div>
  </header>

  <main class="page">
    <div class="shell">
      <section class="panel page-hero">
        <h1>Network status</h1>
        <p>
          Current status for regional ingress and edge services. Last updated {{UPDATED_AT}}.
        </p>
      </section>

      <section class="status-table">
        <div class="panel status-row">
          <div>
            <strong>Hong Kong ingress</strong>
            <span>Regional access and transport handoff</span>
          </div>
          <span class="pill good">Operational</span>
          <span>{{UPDATED_AT}}</span>
        </div>
        <div class="panel status-row">
          <div>
            <strong>Singapore ingress</strong>
            <span>Regional access and transport handoff</span>
          </div>
          <span class="pill good">Operational</span>
          <span>{{UPDATED_AT}}</span>
        </div>
        <div class="panel status-row">
          <div>
            <strong>Japan ingress</strong>
            <span>Regional access and transport handoff</span>
          </div>
          <span class="pill good">Operational</span>
          <span>{{UPDATED_AT}}</span>
        </div>
        <div class="panel status-row">
          <div>
            <strong>United States ingress</strong>
            <span>Regional access and transport handoff</span>
          </div>
          <span class="pill good">Operational</span>
          <span>{{UPDATED_AT}}</span>
        </div>
      </section>
    </div>
  </main>

  <footer class="footer">
    <div class="shell footer-row">
      <span>SSW Edge status</span>
      <span>{{HOSTNAME}}</span>
    </div>
  </footer>
</body>
</html>`

const coverDocsHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SSW Edge Docs</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <header class="site-header">
    <div class="shell header-row">
      <div class="brand">
        <div class="brand-mark">SE</div>
        <div class="brand-copy">
          <strong>SSW Edge</strong>
          <span>{{REGION_LABEL}}</span>
        </div>
      </div>
      <nav class="nav">
        <a href="/">Overview</a>
        <a href="/status.html">Status</a>
        <a class="active" href="/docs.html">Docs</a>
      </nav>
    </div>
  </header>

  <main class="page">
    <div class="shell">
      <section class="panel page-hero">
        <h1>Integration notes</h1>
        <p>
          This hostname belongs to the SSW Edge regional ingress layer. Service consumers typically
          connect using region-specific hostnames with transport parameters negotiated over TLS.
        </p>
      </section>

      <section class="docs-grid">
        <article class="panel doc-card">
          <h2>Regional addressing</h2>
          <p>
            Use the region-specific hostname assigned to your ingress profile. Multiple front-door
            entries may terminate on different regions while still dispatching based on SNI.
          </p>
          <code>endpoint = "{{HOSTNAME}}"</code>
        </article>

        <article class="panel doc-card">
          <h2>Transport expectations</h2>
          <p>
            Edge listeners accept standard TLS traffic and maintain compatibility with multi-region
            ingress balancing. Health and routing policies are applied by the transport layer.
          </p>
          <code>tls = enabled
sni = "{{HOSTNAME}}"
region = "{{REGION_LABEL}}"</code>
        </article>

        <article class="panel doc-card">
          <h2>Status workflow</h2>
          <p>
            Regional health changes are propagated through ingress monitoring and surfaced through
            internal telemetry channels on a rolling basis.
          </p>
          <code>status: operational
updated_at: {{UPDATED_AT}}</code>
        </article>
      </section>
    </div>
  </main>

  <footer class="footer">
    <div class="shell footer-row">
      <span>SSW Edge docs</span>
      <span>{{HOSTNAME}}</span>
    </div>
  </footer>
</body>
</html>`

func collectHosts(node *panel.NodeInfo) []string {
	set := map[string]struct{}{}
	out := make([]string, 0, 4)
	appendHost := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		if _, ok := set[host]; ok {
			return
		}
		set[host] = struct{}{}
		out = append(out, host)
	}

	appendHost(node.Host)
	for _, name := range node.TLSSettings.EffectiveServerNames() {
		appendHost(name)
	}
	return out
}

func quote(v string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + replacer.Replace(v) + `"`
}

type authRequest struct {
	User string `json:"user"`
	IP   string `json:"ip"`
}

type trafficCounter struct {
	uid  int
	mu   sync.Mutex
	up   int64
	down int64
}

func (t *trafficCounter) add(upload, download int64) {
	if upload <= 0 && download <= 0 {
		return
	}
	t.mu.Lock()
	t.up += upload
	t.down += download
	t.mu.Unlock()
}

func (t *trafficCounter) snapshotIfAbove(minTraffic int) (panel.UserTraffic, bool) {
	threshold := int64(minTraffic) * 1000
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.up+t.down <= threshold {
		return panel.UserTraffic{}, false
	}
	data := panel.UserTraffic{
		UID:      t.uid,
		Upload:   t.up,
		Download: t.down,
	}
	t.up = 0
	t.down = 0
	return data, true
}

type tunnelEvent struct {
	Type     string `json:"type"`
	User     string `json:"user"`
	IP       string `json:"ip"`
	Target   string `json:"target"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
}

const eventPrefix = "V2NAIVE_EVENT "

func (s *Server) consumeOutput(reader io.Reader, stderr bool) {
	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 128*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, eventPrefix); idx >= 0 {
			s.handleEventLine(line[idx+len(eventPrefix):])
			continue
		}
		entry := log.WithField("node_id", s.node.Id)
		if stderr {
			entry.Info("[caddy] " + line)
		} else {
			entry.Info("[caddy] " + line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.WithFields(log.Fields{
			"node_id": s.node.Id,
			"err":     err,
		}).Error("read caddy output failed")
	}
}

func (s *Server) handleEventLine(raw string) {
	var event tunnelEvent
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		log.WithFields(log.Fields{
			"node_id": s.node.Id,
			"err":     err,
			"raw":     raw,
		}).Warn("parse caddy tunnel event failed")
		return
	}

	switch event.Type {
	case "open":
		s.statsMu.Lock()
		if _, ok := s.online[event.User]; !ok {
			s.online[event.User] = map[string]int{}
		}
		s.online[event.User][event.IP]++
		s.statsMu.Unlock()
	case "close":
		s.getCounter(event.User).add(event.Upload, event.Download)
		s.limiter.ReleaseIP(event.User, event.IP)
		s.statsMu.Lock()
		if ipMap, ok := s.online[event.User]; ok {
			if ipMap[event.IP] <= 1 {
				delete(ipMap, event.IP)
			} else {
				ipMap[event.IP]--
			}
			if len(ipMap) == 0 {
				delete(s.online, event.User)
			}
		}
		s.statsMu.Unlock()
	}
}

func (s *Server) replaceUsers(users []panel.UserInfo) {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	nextUsers := make(map[string]panel.UserInfo, len(users))
	for _, user := range users {
		nextUsers[user.Uuid] = user
	}
	s.users = nextUsers
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	for uuid := range s.stats {
		if _, ok := nextUsers[uuid]; !ok {
			delete(s.stats, uuid)
		}
	}
	for uuid := range s.online {
		if _, ok := nextUsers[uuid]; !ok {
			delete(s.online, uuid)
		}
	}
	for _, user := range users {
		if _, ok := s.stats[user.Uuid]; !ok {
			s.stats[user.Uuid] = &trafficCounter{uid: user.Id}
		} else {
			s.stats[user.Uuid].uid = user.Id
		}
	}
}

func (s *Server) applyUserDelta(added, deleted, modified []panel.UserInfo) {
	s.usersMu.Lock()
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	defer s.usersMu.Unlock()

	for _, user := range deleted {
		delete(s.users, user.Uuid)
		delete(s.stats, user.Uuid)
		delete(s.online, user.Uuid)
	}
	for _, user := range added {
		s.users[user.Uuid] = user
		if _, ok := s.stats[user.Uuid]; !ok {
			s.stats[user.Uuid] = &trafficCounter{uid: user.Id}
		}
	}
	for _, user := range modified {
		s.users[user.Uuid] = user
		if stat, ok := s.stats[user.Uuid]; ok {
			stat.uid = user.Id
		} else {
			s.stats[user.Uuid] = &trafficCounter{uid: user.Id}
		}
	}
}

func (s *Server) getCounter(uuid string) *trafficCounter {
	s.statsMu.RLock()
	counter, ok := s.stats[uuid]
	s.statsMu.RUnlock()
	if ok {
		return counter
	}

	user := s.userByUUID(uuid)

	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	if counter, ok = s.stats[uuid]; ok {
		return counter
	}
	counter = &trafficCounter{}
	if user.Id != 0 {
		counter.uid = user.Id
	}
	s.stats[uuid] = counter
	return counter
}

func (s *Server) userSnapshot() []panel.UserInfo {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	users := make([]panel.UserInfo, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}
	return users
}

func (s *Server) userByUUID(uuid string) panel.UserInfo {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	return s.users[uuid]
}

func (s *Server) startAuthServerLocked() error {
	if s.authLn != nil {
		return nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	s.authLn = ln
	s.authAddr = ln.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/release", s.handleRelease)
	s.authServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	go func() {
		if err := s.authServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.WithFields(log.Fields{
				"node_id": s.node.Id,
				"err":     err,
			}).Error("caddy auth server failed")
		}
	}()
	return nil
}

func (s *Server) stopAuthServerLocked() {
	if s.authServer != nil {
		_ = s.authServer.Close()
	}
	if s.authLn != nil {
		_ = s.authLn.Close()
	}
	s.authServer = nil
	s.authLn = nil
	s.authAddr = ""
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	defer r.Body.Close()
	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	speedLimit, reject := s.limiter.Authorize(req.User, req.IP)
	if reject {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{
		"speed_limit": speedLimit,
	})
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	defer r.Body.Close()
	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.limiter.ReleaseIP(req.User, req.IP)
	w.WriteHeader(http.StatusNoContent)
}
