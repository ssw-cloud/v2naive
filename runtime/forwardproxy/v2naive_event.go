package forwardproxy

import (
	"encoding/json"
	"log"
)

const v2naiveEventPrefix = "V2NAIVE_EVENT "

type v2naiveTunnelEvent struct {
	Type     string `json:"type"`
	User     string `json:"user"`
	UserID   int    `json:"user_id,omitempty"`
	IP       string `json:"ip"`
	Host     string `json:"host,omitempty"`
	Target   string `json:"target,omitempty"`
	Upload   int64  `json:"upload,omitempty"`
	Download int64  `json:"download,omitempty"`
	Duration int64  `json:"duration_ms,omitempty"`
}

func emitV2naiveEvent(event v2naiveTunnelEvent) {
	body, err := json.Marshal(event)
	if err != nil {
		return
	}
	log.Print(v2naiveEventPrefix + string(body))
}
