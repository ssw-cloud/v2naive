package main

import (
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
