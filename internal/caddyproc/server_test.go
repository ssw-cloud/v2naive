package caddyproc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
		"order forward_proxy first",
		":443, us.sswnat.com, naive.example.com {",
		"bind 0.0.0.0",
		"tls \"/etc/v2naive/fullchain.cer\" \"/etc/v2naive/cert.key\"",
		"basic_auth \"user-a\" \"user-a\"",
		"basic_auth \"user-b\" \"user-b\"",
		"probe_resistance",
		"hide_ip",
		"hide_via",
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
