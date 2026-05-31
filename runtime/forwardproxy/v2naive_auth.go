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
	User   string `json:"user"`
	IP     string `json:"ip"`
	Host   string `json:"host,omitempty"`
	Target string `json:"target,omitempty"`
}

type v2naiveAuthResponse struct {
	SpeedLimit int `json:"speed_limit"`
	UserID     int `json:"user_id"`
}

type v2naiveAuthError struct {
	StatusCode int
	Reason     string `json:"reason"`
	UserID     int    `json:"user_id"`
}

func (e v2naiveAuthError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("auth status %d: %s", e.StatusCode, e.Reason)
	}
	return fmt.Sprintf("auth status %d", e.StatusCode)
}

func isV2NaiveUnauthorized(err error) bool {
	authErr, ok := err.(v2naiveAuthError)
	return ok && authErr.Reason == "unauthorized"
}

func authorizeV2naiveUser(user, ip, host, target string) (v2naiveAuthResponse, error) {
	authURL := os.Getenv("V2NAIVE_AUTH_URL")
	if authURL == "" || user == "" || ip == "" {
		return v2naiveAuthResponse{}, nil
	}

	body, err := json.Marshal(v2naiveAuthRequest{
		User:   user,
		IP:     ip,
		Host:   host,
		Target: target,
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
		authErr := v2naiveAuthError{StatusCode: resp.StatusCode}
		_ = json.NewDecoder(resp.Body).Decode(&authErr)
		authErr.StatusCode = resp.StatusCode
		return v2naiveAuthResponse{}, authErr
	}

	var authResp v2naiveAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return v2naiveAuthResponse{}, err
	}
	return authResp, nil
}
