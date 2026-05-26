package panel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"
	"github.com/ssw-cloud/v2naive/internal/conf"
	"github.com/vmihailenco/msgpack/v5"
)

type Client struct {
	client           *resty.Client
	APIHost          string
	Token            string
	NodeID           int
	nodeEtag         string
	userEtag         string
	responseBodyHash string
}

type NodeInfo struct {
	Id           int
	Tag          string
	Protocol     string
	Host         string      `json:"host"`
	ListenIP     string      `json:"listen_ip"`
	ServerPort   int         `json:"server_port"`
	TLS          int         `json:"tls"`
	TLSSettings  TlsSettings `json:"tls_settings"`
	BaseConfig   BaseConfig  `json:"base_config"`
	CertInfo     *CertInfo
	PushInterval time.Duration
	PullInterval time.Duration
}

type BaseConfig struct {
	PushInterval           int `json:"push_interval"`
	PullInterval           int `json:"pull_interval"`
	DeviceOnlineMinTraffic int `json:"device_online_min_traffic"`
	NodeReportMinTraffic   int `json:"node_report_min_traffic"`
}

type TlsSettings struct {
	ServerName       string   `json:"server_name"`
	ServerNames      []string `json:"server_names"`
	CertMode         string   `json:"cert_mode"`
	CertFile         string   `json:"cert_file"`
	KeyFile          string   `json:"key_file"`
	Provider         string   `json:"provider"`
	DNSEnv           string   `json:"dns_env"`
	RejectUnknownSni string   `json:"reject_unknown_sni"`
	AllowInsecure    int      `json:"allow_insecure"`
}

type CertInfo struct {
	CertMode         string
	CertFile         string
	KeyFile          string
	Email            string
	CertDomain       string
	DNSEnv           map[string]string
	Provider         string
	RejectUnknownSni bool
}

type UserInfo struct {
	Id          int    `json:"id" msgpack:"id"`
	Uuid        string `json:"uuid" msgpack:"uuid"`
	SpeedLimit  int    `json:"speed_limit" msgpack:"speed_limit"`
	DeviceLimit int    `json:"device_limit" msgpack:"device_limit"`
}

type UserListBody struct {
	Users []UserInfo `json:"users" msgpack:"users"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

type UserTraffic struct {
	UID      int
	Upload   int64
	Download int64
}

type OnlineUser struct {
	UID int
	IP  string
}

func New(c *conf.NodeConfig) (*Client, error) {
	client := resty.New()
	retryCount := conf.DefaultNodeRetryCount
	if c.RetryCount != nil {
		retryCount = *c.RetryCount
	}
	client.SetRetryCount(retryCount)
	client.SetHeader("User-Agent", fmt.Sprintf("v2naive go-resty/%s", resty.Version))
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(time.Duration(conf.DefaultNodeTimeout) * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var respErr *resty.ResponseError
		if errors.As(err, &respErr) {
			logrus.Error(respErr.Err)
		}
	})
	client.SetBaseURL(c.APIHost)
	client.SetQueryParams(map[string]string{
		"node_type": "v2node",
		"node_id":   strconv.Itoa(c.NodeID),
		"token":     c.Key,
	})
	return &Client{
		client:  client,
		Token:   c.Key,
		APIHost: c.APIHost,
		NodeID:  c.NodeID,
	}, nil
}

func (c *Client) GetNodeInfo(ctx context.Context) (*NodeInfo, error) {
	const path = "/api/v2/server/config"
	resp, err := c.client.R().
		SetContext(ctx).
		SetHeader("If-None-Match", c.nodeEtag).
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("received nil response")
	}
	if resp.StatusCode() == 304 {
		return nil, nil
	}

	hash := sha256.Sum256(resp.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}
	c.responseBodyHash = newBodyHash
	c.nodeEtag = strings.Trim(resp.Header().Get("ETag"), "\"")

	var cfg NodeInfo
	if err := json.Unmarshal(resp.Body(), &cfg); err != nil {
		return nil, fmt.Errorf("decode node params error: %w", err)
	}
	if cfg.Protocol != "naive" {
		return nil, fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}
	cfg.Id = c.NodeID
	cfg.Tag = fmt.Sprintf("[%s]-naive:%d", c.APIHost, c.NodeID)
	cfg.PushInterval = time.Duration(cfg.BaseConfig.PushInterval) * time.Second
	cfg.PullInterval = time.Duration(cfg.BaseConfig.PullInterval) * time.Second

	certFile := cfg.TLSSettings.CertFile
	keyFile := cfg.TLSSettings.KeyFile
	if certFile == "" {
		certFile = filepath.Join("/etc/v2naive", fmt.Sprintf("naive%d.cer", c.NodeID))
	}
	if keyFile == "" {
		keyFile = filepath.Join("/etc/v2naive", fmt.Sprintf("naive%d.key", c.NodeID))
	}
	dnsEnv := map[string]string{}
	if cfg.TLSSettings.DNSEnv != "" {
		pairs := strings.Split(cfg.TLSSettings.DNSEnv, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				dnsEnv[kv[0]] = kv[1]
			}
		}
	}
	certDomain := cfg.TLSSettings.PrimaryServerName()
	if certDomain == "" {
		certDomain = cfg.Host
	}
	cfg.CertInfo = &CertInfo{
		CertMode:         cfg.TLSSettings.CertMode,
		CertFile:         certFile,
		KeyFile:          keyFile,
		Email:            "node@v2board.com",
		CertDomain:       certDomain,
		DNSEnv:           dnsEnv,
		Provider:         cfg.TLSSettings.Provider,
		RejectUnknownSni: cfg.TLSSettings.RejectUnknownSni == "1",
	}

	return &cfg, nil
}

func (t TlsSettings) EffectiveServerNames() []string {
	if len(t.ServerNames) > 0 {
		return t.ServerNames
	}
	if t.ServerName == "" {
		return nil
	}
	return []string{t.ServerName}
}

func (t TlsSettings) PrimaryServerName() string {
	names := t.EffectiveServerNames()
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func (c *Client) GetUserList(ctx context.Context) ([]UserInfo, error) {
	const path = "/api/v1/server/UniProxy/user"
	resp, err := c.client.R().
		SetContext(ctx).
		SetHeader("If-None-Match", c.userEtag).
		SetHeader("X-Response-Format", "msgpack").
		SetDoNotParseResponse(true).
		Get(path)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.RawResponse == nil {
		return nil, fmt.Errorf("received nil response or raw response")
	}
	defer resp.RawResponse.Body.Close()

	if resp.StatusCode() == 304 {
		return nil, nil
	}

	userList := &UserListBody{}
	if strings.Contains(resp.Header().Get("Content-Type"), "application/x-msgpack") {
		if err := msgpack.NewDecoder(resp.RawResponse.Body).Decode(userList); err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
	} else if err := json.NewDecoder(resp.RawResponse.Body).Decode(userList); err != nil {
		return nil, fmt.Errorf("decode user list error: %w", err)
	}
	c.userEtag = resp.Header().Get("ETag")
	return userList.Users, nil
}

func (c *Client) GetUserAlive(ctx context.Context) (map[int]int, error) {
	const path = "/api/v1/server/UniProxy/alivelist"
	resp, err := c.client.R().
		SetContext(ctx).
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return map[int]int{}, nil
	}
	if resp == nil || resp.RawResponse == nil || resp.StatusCode() >= 399 {
		return map[int]int{}, nil
	}
	defer resp.RawResponse.Body.Close()

	alive := &AliveMap{}
	if err := json.Unmarshal(resp.Body(), alive); err != nil {
		return map[int]int{}, nil
	}
	if alive.Alive == nil {
		return map[int]int{}, nil
	}
	return alive.Alive, nil
}

func (c *Client) ReportUserTraffic(ctx context.Context, userTraffic []UserTraffic) error {
	data := make(map[int][]int64, len(userTraffic))
	for _, traffic := range userTraffic {
		data[traffic.UID] = []int64{traffic.Upload, traffic.Download}
	}
	const path = "/api/v1/server/UniProxy/push"
	_, err := c.client.R().
		SetContext(ctx).
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	return err
}

func (c *Client) ReportNodeOnlineUsers(ctx context.Context, data map[int][]string) error {
	const path = "/api/v1/server/UniProxy/alive"
	_, err := c.client.R().
		SetContext(ctx).
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	return err
}
