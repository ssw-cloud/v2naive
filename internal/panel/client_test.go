package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ssw-cloud/v2naive/internal/conf"
)

func TestGetNodeInfoUsesDefaultCertPaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/config" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"protocol": "naive",
			"host": "node.example.com",
			"server_port": 443,
			"tls": 1,
			"tls_settings": {
				"server_name": "node.example.com",
				"cert_mode": "dns"
			},
			"base_config": {
				"push_interval": 60,
				"pull_interval": 60
			}
		}`))
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{
		APIHost: server.URL,
		NodeID:  117,
		Key:     "token",
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	info, err := client.GetNodeInfo(context.Background())
	if err != nil {
		t.Fatalf("GetNodeInfo returned error: %v", err)
	}
	if info.CertInfo.CertFile != DefaultCertFile {
		t.Fatalf("expected default cert file %q, got %q", DefaultCertFile, info.CertInfo.CertFile)
	}
	if info.CertInfo.KeyFile != DefaultKeyFile {
		t.Fatalf("expected default key file %q, got %q", DefaultKeyFile, info.CertInfo.KeyFile)
	}
}

func TestReportUserTrafficReturnsStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/push" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{
		APIHost: server.URL,
		NodeID:  117,
		Key:     "token",
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	err = client.ReportUserTraffic(context.Background(), []UserTraffic{
		{UID: 7, Upload: 100, Download: 200},
	})
	if err == nil {
		t.Fatal("expected report status error")
	}
}
