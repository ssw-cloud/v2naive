package main

import (
	"os/exec"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
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
