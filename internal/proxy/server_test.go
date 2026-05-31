package proxy

import (
	"testing"

	panel "github.com/ssw-cloud/v2naive/internal/panel"
)

func TestTrafficSnapshotRequiresConfirm(t *testing.T) {
	server := New(&panel.NodeInfo{Id: 1}, []panel.UserInfo{
		{Id: 7, Uuid: "user-1"},
	}, nil)

	counter := server.getCounter("user-1")
	counter.addUpload(100)
	counter.addDownload(200)

	traffic := server.GetUserTrafficSlice(0)
	if len(traffic) != 1 {
		t.Fatalf("expected one traffic report, got %+v", traffic)
	}
	if traffic[0].UID != 7 || traffic[0].UUID != "user-1" || traffic[0].Upload != 100 || traffic[0].Download != 200 {
		t.Fatalf("unexpected traffic snapshot: %+v", traffic[0])
	}
	if next := server.GetUserTrafficSlice(0); len(next) != 1 {
		t.Fatalf("expected traffic to stay pending before confirm, got %+v", next)
	}

	server.ConfirmUserTraffic(traffic)
	if next := server.GetUserTrafficSlice(0); len(next) != 0 {
		t.Fatalf("expected traffic to clear after confirm, got %+v", next)
	}
}

func TestPendingTrafficSurvivesUserDeleteUntilConfirm(t *testing.T) {
	server := New(&panel.NodeInfo{Id: 1}, []panel.UserInfo{
		{Id: 7, Uuid: "user-1"},
	}, nil)

	counter := server.getCounter("user-1")
	counter.addUpload(100)
	counter.addDownload(200)
	server.UpdateUsers(nil, []panel.UserInfo{{Id: 7, Uuid: "user-1"}}, nil, nil)

	traffic := server.GetUserTrafficSlice(0)
	if len(traffic) != 1 || traffic[0].UID != 7 || traffic[0].Upload != 100 || traffic[0].Download != 200 {
		t.Fatalf("pending traffic was not preserved after delete: %+v", traffic)
	}

	server.ConfirmUserTraffic(traffic)
	if next := server.GetUserTrafficSlice(0); len(next) != 0 {
		t.Fatalf("expected deleted user's traffic to clear after confirm, got %+v", next)
	}
}
