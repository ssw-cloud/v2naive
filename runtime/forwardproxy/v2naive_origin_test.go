package forwardproxy

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	caddy "github.com/caddyserver/caddy/v2"
)

type nextHandlerFunc func(http.ResponseWriter, *http.Request) error

func (f nextHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

func TestOriginFormRequestFallsThroughToNextHandler(t *testing.T) {
	handler := Handler{
		AuthCredentials: [][]byte{EncodeAuthCredentials("user", "pass")},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	called := false
	err := handler.ServeHTTP(rec, req, nextHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("cover"))
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}
	if !called {
		t.Fatal("expected origin-form request to fall through to next handler")
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "cover" {
		t.Fatalf("unexpected response: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestV2NaiveAuthAcceptsMatchingUUIDCredentials(t *testing.T) {
	handler := Handler{V2NaiveAuth: true}
	req := httptest.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user-uuid:user-uuid")))
	repl := caddy.NewReplacer()
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))

	if err := handler.checkV2NaiveCredentials(req); err != nil {
		t.Fatalf("checkV2NaiveCredentials returned error: %v", err)
	}
	userID, _ := repl.GetString("http.auth.user.id")
	if userID != "user-uuid" {
		t.Fatalf("expected user id to be captured, got %q", userID)
	}
}

func TestV2NaiveAuthRejectsMismatchedPassword(t *testing.T) {
	handler := Handler{V2NaiveAuth: true}
	req := httptest.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user-uuid:wrong")))
	repl := caddy.NewReplacer()
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))

	if err := handler.checkV2NaiveCredentials(req); err == nil {
		t.Fatal("expected mismatched password to be rejected")
	}
	userID, _ := repl.GetString("http.auth.user.id")
	if userID != "invalid:user-uuid" {
		t.Fatalf("expected invalid user marker, got %q", userID)
	}
}

func TestV2NaiveAuthUnknownUserFallsThroughWithProbeResistance(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"reason":"unauthorized","user_id":0}`))
	}))
	defer authServer.Close()
	t.Setenv("V2NAIVE_AUTH_URL", authServer.URL)

	handler := Handler{
		V2NaiveAuth:     true,
		ProbeResistance: &ProbeResistance{},
	}
	req := httptest.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("unknown-user:unknown-user")))
	repl := caddy.NewReplacer()
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
	rec := httptest.NewRecorder()

	called := false
	err := handler.ServeHTTP(rec, req, nextHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}
	if !called {
		t.Fatal("expected unknown user to fall through with probe resistance")
	}
}
