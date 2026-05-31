package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/ssw-cloud/v2naive/internal/conf"
	panel "github.com/ssw-cloud/v2naive/internal/panel"
)

func TestCompactFormatterKeepsAccessLogReadable(t *testing.T) {
	entry := log.NewEntry(log.StandardLogger())
	entry.Time = entry.Time
	entry.Level = log.InfoLevel
	entry.Message = "| node:4 | from 1.2.3.4 |accepted| tcp:github.com:443 | target:140.82.114.4:443 | user_id:7"

	body, err := compactFormatter{}.Format(entry)
	if err != nil {
		t.Fatalf("format failed: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "|accepted| tcp:github.com:443") || !strings.Contains(text, "user_id:7") {
		t.Fatalf("unexpected access log format: %q", text)
	}
	if strings.Contains(text, "level=") || strings.Contains(text, "msg=") || strings.Contains(text, "[INFO]") {
		t.Fatalf("access log should not use structured wrapper: %q", text)
	}
}

func TestVersionFlag(t *testing.T) {
	cmd := exec.Command("go", "run", "-ldflags=-X github.com/ssw-cloud/v2naive/internal/version.Version=test-version -X github.com/ssw-cloud/v2naive/internal/version.Commit=test-commit", ".", "-version")
	body, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version command failed: %v\n%s", err, body)
	}
	text := string(body)
	if !strings.Contains(text, "test-version") || !strings.Contains(text, "test-commit") {
		t.Fatalf("unexpected version output: %q", text)
	}
}

func TestCompactFormatterShowsVersionFields(t *testing.T) {
	entry := log.NewEntry(log.StandardLogger())
	entry.Time = entry.Time
	entry.Level = log.InfoLevel
	entry.Message = "v2naive starting"
	entry.Data = log.Fields{
		"version": "v0.2.11",
		"commit":  "abc123",
	}

	body, err := compactFormatter{}.Format(entry)
	if err != nil {
		t.Fatalf("format failed: %v", err)
	}
	text := string(body)
	for _, needle := range []string{
		"[INFO] v2naive starting",
		"version=v0.2.11",
		"commit=abc123",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("expected %q in %q", needle, text)
		}
	}
}

func TestPanelSnapshotCacheRoundTrip(t *testing.T) {
	controller := &Controller{
		apiClient: &panel.Client{APIHost: "https://panel.example"},
		conf:      &conf.NodeConfig{APIHost: "https://panel.example", NodeID: 42},
		runtime:   conf.RuntimeConfig{WorkingDir: t.TempDir()},
	}

	err := controller.savePanelSnapshot(&panelSnapshot{
		Node: &panel.NodeInfo{
			Protocol: "naive",
			Host:     "edge.example",
			TLSSettings: panel.TlsSettings{
				CertMode: "file",
				CertFile: "/tmp/fullchain.pem",
				KeyFile:  "/tmp/key.pem",
			},
			BaseConfig: panel.BaseConfig{
				PushInterval: 15,
				PullInterval: 30,
			},
		},
		Users: []panel.UserInfo{{Id: 7, Uuid: "user-1"}},
		Alive: map[int]int{7: 1},
	})
	if err != nil {
		t.Fatalf("save panel snapshot failed: %v", err)
	}

	info, err := os.Stat(controller.panelSnapshotPath())
	if err != nil {
		t.Fatalf("stat cache failed: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected cache mode 0600, got %o", info.Mode().Perm())
	}

	loaded, err := controller.readPanelSnapshot()
	if err != nil {
		t.Fatalf("read panel snapshot failed: %v", err)
	}
	if loaded.Node.Id != 42 || loaded.Node.Tag != "[https://panel.example]-naive:42" {
		t.Fatalf("unexpected cached node identity: %+v", loaded.Node)
	}
	if loaded.Node.PushInterval != 15*time.Second || loaded.Node.PullInterval != 30*time.Second {
		t.Fatalf("unexpected cached intervals: push=%s pull=%s", loaded.Node.PushInterval, loaded.Node.PullInterval)
	}
	if loaded.Node.CertInfo == nil || loaded.Node.CertInfo.CertFile != "/tmp/fullchain.pem" || loaded.Node.CertInfo.KeyFile != "/tmp/key.pem" {
		t.Fatalf("unexpected cached cert info: %+v", loaded.Node.CertInfo)
	}
	if len(loaded.Users) != 1 || loaded.Users[0].Id != 7 || loaded.Alive[7] != 1 {
		t.Fatalf("unexpected cached users/alive: users=%+v alive=%+v", loaded.Users, loaded.Alive)
	}
}
