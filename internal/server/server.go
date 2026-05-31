package server

import panel "github.com/ssw-cloud/v2naive/internal/panel"

type Server interface {
	Start() error
	Close() error
	SetAliveList(alive map[int]int)
	UpdateUsers(added, deleted, modified, full []panel.UserInfo)
	GetUserTrafficSlice(reportMin int) []panel.UserTraffic
	ConfirmUserTraffic(reported []panel.UserTraffic)
	GetOnlineDevice() []panel.OnlineUser
}
