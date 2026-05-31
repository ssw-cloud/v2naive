package forwardproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthorizeV2NaiveUserPreservesUnauthorizedReason(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"reason":"unauthorized","user_id":0}`))
	}))
	defer server.Close()
	t.Setenv("V2NAIVE_AUTH_URL", server.URL)

	_, err := authorizeV2naiveUser("unknown-user", "1.2.3.4", "example.com:443", "example.com:443")
	if err == nil {
		t.Fatal("expected authorizeV2naiveUser to reject unknown user")
	}
	if !isV2NaiveUnauthorized(err) {
		t.Fatalf("expected unauthorized error, got %v", err)
	}
}
