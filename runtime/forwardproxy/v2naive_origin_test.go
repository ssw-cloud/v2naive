package forwardproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
