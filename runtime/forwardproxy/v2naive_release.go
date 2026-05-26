package forwardproxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
)

func releaseV2naiveUser(user, ip string) {
	releaseURL := os.Getenv("V2NAIVE_RELEASE_URL")
	if releaseURL == "" || user == "" || ip == "" {
		return
	}

	body, err := json.Marshal(v2naiveAuthRequest{
		User: user,
		IP:   ip,
	})
	if err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodPost, releaseURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v2naiveAuthHTTPClient.Do(req)
	if err == nil && resp != nil {
		resp.Body.Close()
	}
}
