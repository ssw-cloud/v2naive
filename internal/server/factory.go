package server

import (
	"fmt"

	"github.com/ssw-cloud/v2naive/internal/caddyproc"
	"github.com/ssw-cloud/v2naive/internal/conf"
	panel "github.com/ssw-cloud/v2naive/internal/panel"
	"github.com/ssw-cloud/v2naive/internal/proxy"
)

func New(node *panel.NodeInfo, users []panel.UserInfo, alive map[int]int, runtime conf.RuntimeConfig) (Server, error) {
	switch runtime.EngineName() {
	case conf.EngineLegacy:
		return proxy.New(node, users, alive), nil
	case conf.EngineCaddy:
		return caddyproc.New(node, users, alive, runtime), nil
	default:
		return nil, fmt.Errorf("unsupported runtime engine: %s", runtime.Engine)
	}
}
