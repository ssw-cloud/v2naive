package forwardproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

var v2naiveAuthHTTPClient = &http.Client{
	Timeout: 2 * time.Second,
}

type v2naiveAuthRequest struct {
	User string `json:"user"`
	IP   string `json:"ip"`
}

type v2naiveAuthResponse struct {
	SpeedLimit int `json:"speed_limit"`
}

func authorizeV2naiveUser(user, ip string) (v2naiveAuthResponse, error) {
	authURL := os.Getenv("V2NAIVE_AUTH_URL")
	if authURL == "" || user == "" || ip == "" {
		return v2naiveAuthResponse{}, nil
	}

	body, err := json.Marshal(v2naiveAuthRequest{
		User: user,
		IP:   ip,
	})
	if err != nil {
		return v2naiveAuthResponse{}, err
	}

	req, err := http.NewRequest(http.MethodPost, authURL, bytes.NewReader(body))
	if err != nil {
		return v2naiveAuthResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v2naiveAuthHTTPClient.Do(req)
	if err != nil {
		return v2naiveAuthResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return v2naiveAuthResponse{}, fmt.Errorf("auth status %d", resp.StatusCode)
	}

	var authResp v2naiveAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return v2naiveAuthResponse{}, err
	}
	return authResp, nil
}
