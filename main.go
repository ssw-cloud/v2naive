package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/ssw-cloud/v2naive/internal/certutil"
	"github.com/ssw-cloud/v2naive/internal/conf"
	panel "github.com/ssw-cloud/v2naive/internal/panel"
	"github.com/ssw-cloud/v2naive/internal/server"
	"github.com/ssw-cloud/v2naive/internal/task"
	"github.com/ssw-cloud/v2naive/internal/version"
)

type Controller struct {
	apiClient               *panel.Client
	conf                    *conf.NodeConfig
	info                    *panel.NodeInfo
	server                  server.Server
	tag                     string
	userList                []panel.UserInfo
	reloadCh                chan struct{}
	runtime                 conf.RuntimeConfig
	nodeInfoMonitorPeriodic *task.Task
	userReportPeriodic      *task.Task
	renewCertPeriodic       *task.Task
	aliveList               map[int]int
}

type panelSnapshot struct {
	APIHost string           `json:"api_host"`
	NodeID  int              `json:"node_id"`
	Node    *panel.NodeInfo  `json:"node"`
	Users   []panel.UserInfo `json:"users"`
	Alive   map[int]int      `json:"alive"`
	SavedAt time.Time        `json:"saved_at"`
}

func NewController(api *panel.Client, nodeConf *conf.NodeConfig, runtime conf.RuntimeConfig, reloadCh chan struct{}) *Controller {
	return &Controller{
		apiClient: api,
		conf:      nodeConf,
		runtime:   runtime,
		reloadCh:  reloadCh,
	}
}

func (c *Controller) Start() error {
	snapshot, err := c.startupPanelSnapshot()
	if err != nil {
		return err
	}
	node := snapshot.Node
	users := cloneUserList(snapshot.Users)
	aliveMap := cloneAliveList(snapshot.Alive)
	if node.CertInfo == nil {
		return fmt.Errorf("cert info is nil")
	}
	if err := certutil.RequestCert(node.CertInfo); err != nil {
		return fmt.Errorf("request cert error: %w", err)
	}

	c.info = node
	c.userList = users
	c.aliveList = cloneAliveList(aliveMap)
	c.tag = node.Tag
	runtimeServer, err := server.New(node, users, aliveMap, c.runtime)
	if err != nil {
		return fmt.Errorf("create runtime server error: %w", err)
	}
	c.server = runtimeServer
	if err := c.server.Start(); err != nil {
		return fmt.Errorf("start v2naive server error: %w", err)
	}
	if c.runtime.EngineName() == conf.EngineCaddy {
		log.WithField("node_id", node.Id).Info("caddy runtime is active; protocol is served by patched forwardproxy@naive")
	}
	c.startTasks()
	return nil
}

func (c *Controller) Close() {
	if c.nodeInfoMonitorPeriodic != nil {
		c.nodeInfoMonitorPeriodic.Close()
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
	}
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.Close()
	}
	if c.server != nil {
		_ = c.server.Close()
	}
}

func (c *Controller) startTasks() {
	c.nodeInfoMonitorPeriodic = &task.Task{
		Name:     "nodeInfoMonitor",
		Interval: c.info.PullInterval,
		Execute:  c.nodeInfoMonitor,
		ReloadCh: c.reloadCh,
	}
	c.userReportPeriodic = &task.Task{
		Name:     "reportUserTrafficTask",
		Interval: c.info.PushInterval,
		Execute:  c.reportUserTrafficTask,
		ReloadCh: c.reloadCh,
	}
	_ = c.nodeInfoMonitorPeriodic.Start(false)
	_ = c.userReportPeriodic.Start(false)
	if c.info.TLS == 1 && c.info.CertInfo != nil {
		switch c.info.CertInfo.CertMode {
		case "dns", "http":
			c.renewCertPeriodic = &task.Task{
				Name:     "renewCertTask",
				Interval: 24 * time.Hour,
				Execute: func(context.Context) error {
					legoClient, err := certutil.NewLego(c.info.CertInfo)
					if err != nil {
						return err
					}
					renewed, err := legoClient.RenewCert()
					if err != nil {
						return err
					}
					if renewed {
						log.WithField("node_id", c.info.Id).Info("certificate renewed; reloading runtime")
						c.triggerReload()
					}
					return nil
				},
				ReloadCh: c.reloadCh,
			}
			_ = c.renewCertPeriodic.Start(true)
		}
	}
}

func (c *Controller) startupPanelSnapshot() (*panelSnapshot, error) {
	snapshot, err := c.fetchPanelSnapshot(context.Background())
	if err == nil {
		if err := c.savePanelSnapshot(snapshot); err != nil {
			log.WithError(err).Warn("save panel cache failed")
		}
		return snapshot, nil
	}
	if panel.IsAuthStatusError(err) {
		return nil, err
	}

	cached, cacheErr := c.readPanelSnapshot()
	if cacheErr != nil {
		return nil, fmt.Errorf("fetch panel snapshot failed: %w; cached snapshot unavailable: %v", err, cacheErr)
	}
	log.WithFields(log.Fields{
		"node_id":  c.conf.NodeID,
		"saved_at": cached.SavedAt.Format(time.RFC3339),
		"err":      err,
	}).Warn("panel unavailable; starting with cached snapshot")
	return cached, nil
}

func (c *Controller) fetchPanelSnapshot(ctx context.Context) (*panelSnapshot, error) {
	node, err := c.apiClient.GetNodeInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("get node info error: %w", err)
	}
	if node == nil {
		return nil, fmt.Errorf("empty node info")
	}
	if node.Protocol != "naive" {
		return nil, fmt.Errorf("node %d protocol is %s, not naive", node.Id, node.Protocol)
	}
	users, err := c.apiClient.GetUserList(ctx)
	if err != nil {
		return nil, fmt.Errorf("get user list error: %w", err)
	}
	if users == nil {
		return nil, fmt.Errorf("empty user list")
	}
	aliveMap, err := c.apiClient.GetUserAlive(ctx)
	if err != nil {
		return nil, fmt.Errorf("get user alive error: %w", err)
	}
	return &panelSnapshot{
		Node:  node,
		Users: cloneUserList(users),
		Alive: cloneAliveList(aliveMap),
	}, nil
}

func (c *Controller) saveCurrentPanelSnapshot() {
	if c.info == nil {
		return
	}
	if err := c.savePanelSnapshot(&panelSnapshot{
		Node:  c.info,
		Users: c.userList,
		Alive: c.aliveList,
	}); err != nil {
		log.WithError(err).Warn("save panel cache failed")
	}
}

func (c *Controller) savePanelSnapshot(snapshot *panelSnapshot) error {
	if snapshot == nil || snapshot.Node == nil {
		return fmt.Errorf("empty panel snapshot")
	}
	if err := snapshot.Node.Normalize(c.conf.NodeID, c.apiClient.APIHost); err != nil {
		return err
	}
	toSave := panelSnapshot{
		APIHost: c.apiClient.APIHost,
		NodeID:  c.conf.NodeID,
		Node:    snapshot.Node,
		Users:   cloneUserList(snapshot.Users),
		Alive:   cloneAliveList(snapshot.Alive),
		SavedAt: time.Now().UTC(),
	}
	body, err := json.Marshal(toSave)
	if err != nil {
		return err
	}

	cachePath := c.panelSnapshotPath()
	if err := os.MkdirAll(filepath.Dir(cachePath), 0755); err != nil {
		return err
	}
	tmpPath := cachePath + ".tmp"
	if err := os.WriteFile(tmpPath, body, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, cachePath)
}

func (c *Controller) readPanelSnapshot() (*panelSnapshot, error) {
	body, err := os.ReadFile(c.panelSnapshotPath())
	if err != nil {
		return nil, err
	}
	var snapshot panelSnapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Node == nil {
		return nil, fmt.Errorf("cached node info is empty")
	}
	if snapshot.APIHost != "" && snapshot.APIHost != c.apiClient.APIHost {
		return nil, fmt.Errorf("cached api host %q does not match %q", snapshot.APIHost, c.apiClient.APIHost)
	}
	if snapshot.NodeID != 0 && snapshot.NodeID != c.conf.NodeID {
		return nil, fmt.Errorf("cached node id %d does not match %d", snapshot.NodeID, c.conf.NodeID)
	}
	if err := snapshot.Node.Normalize(c.conf.NodeID, c.apiClient.APIHost); err != nil {
		return nil, err
	}
	snapshot.Users = cloneUserList(snapshot.Users)
	snapshot.Alive = cloneAliveList(snapshot.Alive)
	return &snapshot, nil
}

func (c *Controller) panelSnapshotPath() string {
	return filepath.Join(c.runtime.WorkingDir, fmt.Sprintf("node-%d", c.conf.NodeID), "panel-cache.json")
}

func (c *Controller) triggerReload() {
	select {
	case c.reloadCh <- struct{}{}:
	default:
	}
}

func (c *Controller) nodeInfoMonitor(ctx context.Context) error {
	newInfo, err := c.apiClient.GetNodeInfo(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		log.WithError(err).Error("get node info failed")
		return nil
	}
	if newInfo != nil {
		if err := c.savePanelSnapshot(&panelSnapshot{
			Node:  newInfo,
			Users: c.userList,
			Alive: c.aliveList,
		}); err != nil {
			log.WithError(err).Warn("save panel cache failed")
		}
		c.triggerReload()
		return nil
	}

	newUsers, err := c.apiClient.GetUserList(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		log.WithError(err).Error("get user list failed")
		return nil
	}
	newAlive, err := c.apiClient.GetUserAlive(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		log.WithError(err).Error("get alive list failed")
		return nil
	}
	if newAlive != nil {
		c.aliveList = cloneAliveList(newAlive)
		c.server.SetAliveList(newAlive)
	}
	if newUsers == nil {
		c.saveCurrentPanelSnapshot()
		return nil
	}
	deleted, added, modified := compareUserList(c.userList, newUsers)
	if len(added) > 0 || len(deleted) > 0 || len(modified) > 0 {
		c.server.UpdateUsers(added, deleted, modified, newUsers)
		c.userList = cloneUserList(newUsers)
		log.Infof("%s: %d users added, %d deleted, %d modified", c.tag, len(added), len(deleted), len(modified))
	}
	c.saveCurrentPanelSnapshot()
	return nil
}

func (c *Controller) reportUserTrafficTask(ctx context.Context) error {
	reportMin := 0
	deviceMin := 0
	if c.info != nil {
		reportMin = c.info.BaseConfig.NodeReportMinTraffic
		deviceMin = c.info.BaseConfig.DeviceOnlineMinTraffic
	}
	userTraffic := c.server.GetUserTrafficSlice(reportMin)
	if len(userTraffic) > 0 {
		if err := c.apiClient.ReportUserTraffic(ctx, userTraffic); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			log.WithError(err).Info("report user traffic failed")
		} else {
			c.server.ConfirmUserTraffic(userTraffic)
			log.Debugf("%s: reported %d users traffic", c.tag, len(userTraffic))
		}
	}

	onlineDevice := c.server.GetOnlineDevice()
	if len(onlineDevice) == 0 {
		return nil
	}

	noCountUID := map[int]struct{}{}
	for _, traffic := range userTraffic {
		if traffic.Upload+traffic.Download < int64(deviceMin*1000) {
			noCountUID[traffic.UID] = struct{}{}
		}
	}

	reportData := map[int][]string{}
	for _, online := range onlineDevice {
		if _, skip := noCountUID[online.UID]; skip {
			continue
		}
		reportData[online.UID] = append(reportData[online.UID], online.IP)
	}
	if len(reportData) > 0 {
		if err := c.apiClient.ReportNodeOnlineUsers(ctx, reportData); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			log.WithError(err).Info("report online users failed")
		}
	}
	return nil
}

func compareUserList(oldUsers, newUsers []panel.UserInfo) (deleted, added, modified []panel.UserInfo) {
	oldMap := make(map[string]panel.UserInfo, len(oldUsers))
	for _, user := range oldUsers {
		oldMap[user.Uuid] = user
	}
	for _, user := range newUsers {
		if existing, ok := oldMap[user.Uuid]; !ok {
			added = append(added, user)
		} else {
			if existing.SpeedLimit != user.SpeedLimit || existing.DeviceLimit != user.DeviceLimit {
				modified = append(modified, user)
			}
			delete(oldMap, user.Uuid)
		}
	}
	for _, user := range oldMap {
		deleted = append(deleted, user)
	}
	return deleted, added, modified
}

func cloneUserList(in []panel.UserInfo) []panel.UserInfo {
	if len(in) == 0 {
		return []panel.UserInfo{}
	}
	out := make([]panel.UserInfo, len(in))
	copy(out, in)
	return out
}

func cloneAliveList(in map[int]int) map[int]int {
	out := make(map[int]int, len(in))
	for uid, count := range in {
		out[uid] = count
	}
	return out
}

func setupLog(cfg conf.LogConfig) error {
	level, err := log.ParseLevel(cfg.Level)
	if err != nil {
		return err
	}
	log.SetLevel(level)
	log.SetFormatter(compactFormatter{})
	if cfg.Output != "" {
		file, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		log.SetOutput(file)
	}
	return nil
}

type compactFormatter struct{}

func (compactFormatter) Format(entry *log.Entry) ([]byte, error) {
	var builder strings.Builder
	builder.WriteString(entry.Time.Format("2006/01/02 15:04:05"))
	builder.WriteByte(' ')
	if strings.HasPrefix(entry.Message, "| ") {
		builder.WriteString(entry.Message)
		builder.WriteByte('\n')
		return []byte(builder.String()), nil
	}

	builder.WriteByte('[')
	builder.WriteString(strings.ToUpper(entry.Level.String()))
	builder.WriteString("] ")
	builder.WriteString(entry.Message)
	if len(entry.Data) > 0 {
		keys := make([]string, 0, len(entry.Data))
		for key := range entry.Data {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			builder.WriteByte(' ')
			builder.WriteString(key)
			builder.WriteByte('=')
			builder.WriteString(compactLogValue(entry.Data[key]))
		}
	}
	builder.WriteByte('\n')
	return []byte(builder.String()), nil
}

func compactLogValue(value interface{}) string {
	text := fmt.Sprint(value)
	if text == "" {
		return strconv.Quote(text)
	}
	if strings.ContainsAny(text, " \t\r\n\"") {
		return strconv.Quote(text)
	}
	return text
}

func main() {
	configPath := flag.String("config", "config.yml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("v2naive %s commit %s\n", version.Version, version.Commit)
		return
	}

	cfg := conf.New()
	if err := cfg.LoadFromPath(*configPath); err != nil {
		log.Fatalf("load config failed: %v", err)
	}
	if err := setupLog(cfg.LogConfig); err != nil {
		log.Fatalf("setup log failed: %v", err)
	}
	log.WithFields(log.Fields{
		"version": version.Version,
		"commit":  version.Commit,
	}).Info("v2naive starting")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if len(cfg.NodeConfigs) == 0 {
		log.Fatal("no node configured")
	}

	for i := range cfg.NodeConfigs {
		nodeCfg := cfg.NodeConfigs[i]
		go runNode(ctx, &nodeCfg, cfg.RuntimeConfig)
	}

	<-ctx.Done()
	log.Info("v2naive stopped")
}

func runNode(ctx context.Context, nodeCfg *conf.NodeConfig, runtime conf.RuntimeConfig) {
	reloadCh := make(chan struct{}, 1)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		client, err := panel.New(nodeCfg)
		if err != nil {
			log.WithError(err).Error("create panel client failed")
			select {
			case <-time.After(10 * time.Second):
			case <-ctx.Done():
			}
			continue
		}

		controller := NewController(client, nodeCfg, runtime, reloadCh)
		if err := controller.Start(); err != nil {
			log.WithFields(log.Fields{
				"node_id": nodeCfg.NodeID,
				"err":     err,
			}).Error("start node controller failed")
			select {
			case <-time.After(10 * time.Second):
			case <-ctx.Done():
			}
			continue
		}

		select {
		case <-ctx.Done():
			controller.Close()
			return
		case <-reloadCh:
			controller.Close()
			time.Sleep(time.Second)
		}
	}
}
