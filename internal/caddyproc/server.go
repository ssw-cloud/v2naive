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
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "index.html"), []byte(coverPageHTML()), 0644)
}

func (s *Server) coverDir() string {
	return filepath.Join(s.workDir, "cover")
}

func coverPageHTML() string {
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Welcome</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      color: #202124;
      background: #f8fafd;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main {
      width: min(680px, calc(100% - 48px));
    }
    h1 {
      margin: 0 0 12px;
      font-size: 32px;
      font-weight: 600;
      letter-spacing: 0;
    }
    p {
      margin: 0;
      color: #5f6368;
      font-size: 16px;
      line-height: 1.7;
    }
  </style>
</head>
<body>
  <main>
    <h1>Welcome</h1>
    <p>This site is running normally.</p>
  </main>
</body>
</html>`
}

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
