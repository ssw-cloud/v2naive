package certutil

import (
	"testing"
	"time"

	panel "github.com/ssw-cloud/v2naive/internal/panel"
)

func TestLockCertSerializesSameCert(t *testing.T) {
	cert := &panel.CertInfo{
		CertMode:   "dns",
		CertDomain: "us-west1.sswnat.com",
		CertFile:   "/etc/v2naive/fullchain.cer",
		KeyFile:    "/etc/v2naive/cert.key",
		Provider:   "cloudflare",
	}

	unlockFirst := lockCert(cert)
	acquiredSecond := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		unlockSecond := lockCert(cert)
		close(acquiredSecond)
		unlockSecond()
	}()

	select {
	case <-acquiredSecond:
		t.Fatal("second lock acquired before first lock was released")
	case <-time.After(50 * time.Millisecond):
	}

	unlockFirst()
	select {
	case <-acquiredSecond:
	case <-time.After(time.Second):
		t.Fatal("second lock did not acquire after first lock was released")
	}
	<-done
}
