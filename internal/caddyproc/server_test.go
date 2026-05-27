package caddyproc

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/ssw-cloud/v2naive/internal/conf"
	panel "github.com/ssw-cloud/v2naive/internal/panel"
)

func TestRenderConfigIncludesNaiveForwardProxyShape(t *testing.T) {
	server := New(&panel.NodeInfo{
		Id:         3,
		Host:       "us.sswnat.com",
		ListenIP:   "0.0.0.0",
		ServerPort: 443,
		CertInfo: &panel.CertInfo{
			CertFile: "/etc/v2naive/fullchain.cer",
			KeyFile:  "/etc/v2naive/cert.key",
		},
		TLSSettings: panel.TlsSettings{
			ServerName:  "us.sswnat.com",
			ServerNames: []string{"us.sswnat.com", "naive.example.com"},
		},
	}, []panel.UserInfo{
		{Uuid: "user-b"},
		{Uuid: "user-a"},
	}, nil, conf.RuntimeConfig{
		CaddyPath:     "/opt/v2naive/caddy",
		WorkingDir:    "/var/lib/v2naive",
		AdminPortBase: 22019,
	})

	text := string(server.renderConfig())
	for _, needle := range []string{
		"admin 127.0.0.1:22022",
		"auto_https off",
		"order forward_proxy first",
		"protocols h1 h2",
		":443, us.sswnat.com, naive.example.com {",
		"bind 0.0.0.0",
		"tls \"/etc/v2naive/fullchain.cer\" \"/etc/v2naive/cert.key\"",
		"basic_auth \"user-a\" \"user-a\"",
		"basic_auth \"user-b\" \"user-b\"",
		"probe_resistance",
		"hide_ip",
		"hide_via",
		"dial_timeout 10s",
		"max_idle_conns 1024",
		"max_idle_conns_per_host 64",
		"allow all",
		"root * \"/var/lib/v2naive/node-3/cover\"",
		"file_server",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("expected config to contain %q, got:\n%s", needle, text)
		}
	}
}

func TestRenderConfigLocksProxyWhenNoUsers(t *testing.T) {
	server := New(&panel.NodeInfo{
		Id:         1,
		ServerPort: 443,
		CertInfo: &panel.CertInfo{
			CertFile: "/tmp/cert.pem",
			KeyFile:  "/tmp/key.pem",
		},
	}, nil, nil, conf.RuntimeConfig{
		CaddyPath:     "/opt/v2naive/caddy",
		WorkingDir:    "/var/lib/v2naive",
		AdminPortBase: 22019,
	})

	text := string(server.renderConfig())
	if !strings.Contains(text, "basic_auth \"__disabled__\" \"__disabled__\"") {
		t.Fatalf("expected placeholder auth when user list is empty, got:\n%s", text)
	}
}

func TestWriteCoverSiteCreatesSSWEdgePages(t *testing.T) {
	workDir := t.TempDir()
	server := New(&panel.NodeInfo{
		Id:         8,
		Host:       "hk.sswnat.com",
		ServerPort: 443,
		CertInfo: &panel.CertInfo{
			CertFile: "/tmp/cert.pem",
			KeyFile:  "/tmp/key.pem",
		},
	}, nil, nil, conf.RuntimeConfig{
		CaddyPath:     "/opt/v2naive/caddy",
		WorkingDir:    workDir,
		AdminPortBase: 22019,
	})

	if err := server.writeCoverSite(); err != nil {
		t.Fatalf("writeCoverSite returned error: %v", err)
	}

	indexHTML, err := os.ReadFile(filepath.Join(server.coverDir(), "index.html"))
	if err != nil {
		t.Fatalf("read index.html failed: %v", err)
	}
	if !strings.Contains(string(indexHTML), "SSW Edge") || !strings.Contains(string(indexHTML), "Hong Kong Edge") {
		t.Fatalf("unexpected index page content:\n%s", string(indexHTML))
	}

	statusHTML, err := os.ReadFile(filepath.Join(server.coverDir(), "status.html"))
	if err != nil {
		t.Fatalf("read status.html failed: %v", err)
	}
	if !strings.Contains(string(statusHTML), "Network status") {
		t.Fatalf("unexpected status page content:\n%s", string(statusHTML))
	}

	docsHTML, err := os.ReadFile(filepath.Join(server.coverDir(), "docs.html"))
	if err != nil {
		t.Fatalf("read docs.html failed: %v", err)
	}
	if !strings.Contains(string(docsHTML), "Integration notes") || !strings.Contains(string(docsHTML), "hk.sswnat.com") {
		t.Fatalf("unexpected docs page content:\n%s", string(docsHTML))
	}
}

func TestTunnelEventsUpdateOnlineAndTraffic(t *testing.T) {
	server := New(&panel.NodeInfo{
		Id:         5,
		ServerPort: 443,
		CertInfo: &panel.CertInfo{
			CertFile: "/tmp/cert.pem",
			KeyFile:  "/tmp/key.pem",
		},
	}, []panel.UserInfo{
		{Id: 7, Uuid: "user-1"},
	}, nil, conf.RuntimeConfig{
		CaddyPath:     "/opt/v2naive/caddy",
		WorkingDir:    "/var/lib/v2naive",
		AdminPortBase: 22019,
	})

	server.handleEventLine(`{"type":"open","user":"user-1","ip":"1.2.3.4","target":"example.com:443"}`)
	online := server.GetOnlineDevice()
	if len(online) != 1 || online[0].UID != 7 || online[0].IP != "1.2.3.4" {
		t.Fatalf("unexpected online users after open event: %+v", online)
	}

	server.handleEventLine(`{"type":"close","user":"user-1","ip":"1.2.3.4","target":"example.com:443","upload":1234,"download":5678}`)
	online = server.GetOnlineDevice()
	if len(online) != 0 {
		t.Fatalf("expected no online users after close event, got %+v", online)
	}

	traffic := server.GetUserTrafficSlice(0)
	if len(traffic) != 1 {
		t.Fatalf("expected one traffic report, got %+v", traffic)
	}
	if traffic[0].UID != 7 || traffic[0].Upload != 1234 || traffic[0].Download != 5678 {
		t.Fatalf("unexpected traffic snapshot: %+v", traffic[0])
	}
	if next := server.GetUserTrafficSlice(0); len(next) != 0 {
		t.Fatalf("expected counters to reset after snapshot, got %+v", next)
	}
}

func TestTunnelEventsAcceptHostAndDurationFields(t *testing.T) {
	server := New(&panel.NodeInfo{
		Id:         5,
		ServerPort: 443,
		CertInfo: &panel.CertInfo{
			CertFile: "/tmp/cert.pem",
			KeyFile:  "/tmp/key.pem",
		},
	}, []panel.UserInfo{
		{Id: 7, Uuid: "user-1"},
	}, nil, conf.RuntimeConfig{
		CaddyPath:     "/opt/v2naive/caddy",
		WorkingDir:    "/var/lib/v2naive",
		AdminPortBase: 22019,
	})

	server.handleEventLine(`{"type":"open","user":"user-1","ip":"1.2.3.4","host":"github.com:443","target":"140.82.114.4:443"}`)
	server.handleEventLine(`{"type":"close","user":"user-1","ip":"1.2.3.4","host":"github.com:443","target":"140.82.114.4:443","upload":100,"download":200,"duration_ms":3000}`)

	traffic := server.GetUserTrafficSlice(0)
	if len(traffic) != 1 || traffic[0].Upload != 100 || traffic[0].Download != 200 {
		t.Fatalf("unexpected traffic snapshot: %+v", traffic)
	}
}

func TestTunnelCloseLogUsesNumericUserID(t *testing.T) {
	server := New(&panel.NodeInfo{
		Id:         5,
		ServerPort: 443,
		CertInfo: &panel.CertInfo{
			CertFile: "/tmp/cert.pem",
			KeyFile:  "/tmp/key.pem",
		},
	}, []panel.UserInfo{
		{Id: 7, Uuid: "user-1"},
	}, nil, conf.RuntimeConfig{
		CaddyPath:     "/opt/v2naive/caddy",
		WorkingDir:    "/var/lib/v2naive",
		AdminPortBase: 22019,
	})

	var out bytes.Buffer
	previousOutput := log.StandardLogger().Out
	previousFormatter := log.StandardLogger().Formatter
	defer func() {
		log.SetOutput(previousOutput)
		log.SetFormatter(previousFormatter)
	}()
	log.SetOutput(&out)
	log.SetFormatter(&log.TextFormatter{DisableTimestamp: true, DisableQuote: true})

	server.handleEventLine(`{"type":"open","user":"user-1","ip":"1.2.3.4","host":"github.com:443","target":"140.82.114.4:443"}`)
	if out.Len() != 0 {
		t.Fatalf("open event should not emit access log, got %q", out.String())
	}

	server.handleEventLine(`{"type":"close","user":"user-1","ip":"1.2.3.4","host":"github.com:443","target":"140.82.114.4:443","upload":100,"download":200,"duration_ms":3000}`)
	text := out.String()
	for _, needle := range []string{
		"from 1.2.3.4",
		"|accepted| tcp:github.com:443",
		"target:140.82.114.4:443",
		"user_id:7",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("expected access log to contain %q, got %q", needle, text)
		}
	}
	for _, needle := range []string{
		"upload:",
		"download:",
		"duration:",
	} {
		if strings.Contains(text, needle) {
			t.Fatalf("access log should not contain %q: %q", needle, text)
		}
	}
	if strings.Contains(text, "user_id:user-1") {
		t.Fatalf("access log should not use uuid as user_id: %q", text)
	}
}

func TestTunnelCloseLogUsesZeroForUnknownNumericUserID(t *testing.T) {
	server := New(&panel.NodeInfo{
		Id:         5,
		ServerPort: 443,
		CertInfo: &panel.CertInfo{
			CertFile: "/tmp/cert.pem",
			KeyFile:  "/tmp/key.pem",
		},
	}, nil, nil, conf.RuntimeConfig{
		CaddyPath:     "/opt/v2naive/caddy",
		WorkingDir:    "/var/lib/v2naive",
		AdminPortBase: 22019,
	})

	text := server.formatAccessLog(tunnelEvent{
		User:   "unknown-uuid",
		IP:     "1.2.3.4",
		Host:   "github.com:443",
		Target: "140.82.114.4:443",
	}, panel.UserInfo{})

	if !strings.Contains(text, "user_id:0") || strings.Contains(text, "unknown-uuid") {
		t.Fatalf("unknown users should not leak uuid in access log: %q", text)
	}
}

func TestNoisyCaddyErrorsAreSuppressed(t *testing.T) {
	for _, text := range []string{
		"write: broken pipe",
		"http2: stream closed",
		"H3_REQUEST_CANCELLED",
		"read: connection reset by peer",
		"use of closed network connection",
	} {
		if !isNoisyCaddyError(text) {
			t.Fatalf("expected %q to be noisy", text)
		}
	}
	if isNoisyCaddyError("dial tcp: i/o timeout") {
		t.Fatal("timeout errors should still be logged")
	}
}

func TestConsumeOutputParsesEmbeddedEventPrefix(t *testing.T) {
	server := New(&panel.NodeInfo{
		Id:         6,
		ServerPort: 443,
		CertInfo: &panel.CertInfo{
			CertFile: "/tmp/cert.pem",
			KeyFile:  "/tmp/key.pem",
		},
	}, []panel.UserInfo{
		{Id: 9, Uuid: "user-2"},
	}, nil, conf.RuntimeConfig{
		CaddyPath:     "/opt/v2naive/caddy",
		WorkingDir:    "/var/lib/v2naive",
		AdminPortBase: 22019,
	})

	stream := strings.NewReader("2026/05/26 07:33:29 info V2NAIVE_EVENT {\"type\":\"open\",\"user\":\"user-2\",\"ip\":\"5.6.7.8\"}\n")
	server.consumeOutput(stream, false)
	online := server.GetOnlineDevice()
	if len(online) != 1 || online[0].UID != 9 || online[0].IP != "5.6.7.8" {
		t.Fatalf("unexpected online users after consumeOutput: %+v", online)
	}
}

func TestConsumeOutputParsesStructuredCaddyJSONEvent(t *testing.T) {
	server := New(&panel.NodeInfo{
		Id:         9,
		ServerPort: 443,
		CertInfo: &panel.CertInfo{
			CertFile: "/tmp/cert.pem",
			KeyFile:  "/tmp/key.pem",
		},
	}, []panel.UserInfo{
		{Id: 12, Uuid: "user-5"},
	}, nil, conf.RuntimeConfig{
		CaddyPath:     "/opt/v2naive/caddy",
		WorkingDir:    "/var/lib/v2naive",
		AdminPortBase: 22019,
	})

	stream := strings.NewReader(`{"level":"info","ts":1780000000.0,"logger":"http.handlers.forward_proxy","msg":"V2NAIVE_EVENT {\"type\":\"close\",\"user\":\"user-5\",\"ip\":\"4.3.2.1\",\"target\":\"example.com:443\",\"upload\":333,\"download\":444}"}` + "\n")
	server.consumeOutput(stream, false)

	traffic := server.GetUserTrafficSlice(0)
	if len(traffic) != 1 {
		t.Fatalf("expected one traffic report, got %+v", traffic)
	}
	if traffic[0].UID != 12 || traffic[0].Upload != 333 || traffic[0].Download != 444 {
		t.Fatalf("unexpected traffic snapshot: %+v", traffic[0])
	}
}

func TestAuthorizeRejectsWhenDeviceLimitReached(t *testing.T) {
	server := New(&panel.NodeInfo{
		Id:         7,
		ServerPort: 443,
		CertInfo: &panel.CertInfo{
			CertFile: "/tmp/cert.pem",
			KeyFile:  "/tmp/key.pem",
		},
	}, []panel.UserInfo{
		{Id: 10, Uuid: "user-3", DeviceLimit: 1},
	}, map[int]int{
		10: 1,
	}, conf.RuntimeConfig{
		CaddyPath:     "/opt/v2naive/caddy",
		WorkingDir:    "/var/lib/v2naive",
		AdminPortBase: 22019,
	})

	request := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(`{"user":"user-3","ip":"9.9.9.9"}`))
	recorder := httptest.NewRecorder()
	server.handleAuthorize(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when device limit is reached, got %d", recorder.Code)
	}
}

func TestAuthorizeReturnsSpeedLimit(t *testing.T) {
	server := New(&panel.NodeInfo{
		Id:         8,
		ServerPort: 443,
		CertInfo: &panel.CertInfo{
			CertFile: "/tmp/cert.pem",
			KeyFile:  "/tmp/key.pem",
		},
	}, []panel.UserInfo{
		{Id: 11, Uuid: "user-4", SpeedLimit: 20},
	}, nil, conf.RuntimeConfig{
		CaddyPath:     "/opt/v2naive/caddy",
		WorkingDir:    "/var/lib/v2naive",
		AdminPortBase: 22019,
	})

	request := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(`{"user":"user-4","ip":"8.8.8.8"}`))
	recorder := httptest.NewRecorder()
	server.handleAuthorize(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var body map[string]int
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body failed: %v", err)
	}
	if body["speed_limit"] != 20 {
		t.Fatalf("expected speed_limit=20, got %+v", body)
	}
}
