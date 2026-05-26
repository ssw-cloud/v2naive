package conf

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

const DefaultNodeRetryCount = 1
const DefaultNodeTimeout = 15

type Conf struct {
	LogConfig     LogConfig     `mapstructure:"Log"`
	RuntimeConfig RuntimeConfig `mapstructure:"Runtime"`
	NodeConfigs   []NodeConfig  `mapstructure:"Nodes"`
}

type LogConfig struct {
	Level  string `mapstructure:"Level"`
	Output string `mapstructure:"Output"`
}

type NodeConfig struct {
	APIHost    string `mapstructure:"ApiHost"`
	NodeID     int    `mapstructure:"NodeID"`
	Key        string `mapstructure:"ApiKey"`
	Timeout    int    `mapstructure:"Timeout"`
	RetryCount *int   `mapstructure:"RetryCount"`
}

const (
	EngineLegacy = "legacy"
	EngineCaddy  = "caddy"
)

type RuntimeConfig struct {
	Engine        string `mapstructure:"Engine"`
	CaddyPath     string `mapstructure:"CaddyPath"`
	WorkingDir    string `mapstructure:"WorkingDir"`
	AdminPortBase int    `mapstructure:"AdminPortBase"`
}

func New() *Conf {
	return &Conf{
		LogConfig: LogConfig{
			Level: "info",
		},
		RuntimeConfig: RuntimeConfig{
			Engine:        EngineLegacy,
			CaddyPath:     "/opt/v2naive/caddy",
			WorkingDir:    "/var/lib/v2naive",
			AdminPortBase: 22019,
		},
	}
}

func (c *Conf) LoadFromPath(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open config file error: %w", err)
	}
	defer f.Close()

	v := viper.New()
	v.SetConfigFile(filePath)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config file error: %w", err)
	}
	if err := v.Unmarshal(c); err != nil {
		return fmt.Errorf("unmarshal config error: %w", err)
	}
	for i := range c.NodeConfigs {
		if c.NodeConfigs[i].RetryCount == nil {
			c.NodeConfigs[i].RetryCount = intPtr(DefaultNodeRetryCount)
		}
	}
	c.RuntimeConfig.normalize()
	return nil
}

func intPtr(v int) *int {
	return &v
}

func (c RuntimeConfig) EngineName() string {
	engine := strings.TrimSpace(strings.ToLower(c.Engine))
	if engine == "" {
		return EngineLegacy
	}
	return engine
}

func (c *RuntimeConfig) normalize() {
	if c.Engine == "" {
		c.Engine = EngineLegacy
	}
	if c.CaddyPath == "" {
		c.CaddyPath = "/opt/v2naive/caddy"
	}
	if c.WorkingDir == "" {
		c.WorkingDir = "/var/lib/v2naive"
	}
	if c.AdminPortBase == 0 {
		c.AdminPortBase = 22019
	}
}
