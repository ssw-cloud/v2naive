package forwardproxy

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

var v2naiveUserLimiters sync.Map

type dynamicRateLimiter struct {
	mu          sync.RWMutex
	limiter     *rate.Limiter
	bytesPerSec int
}

func getUserRateLimiter(user string, speedLimit int) *dynamicRateLimiter {
	if user == "" {
		return nil
	}
	if speedLimit <= 0 {
		if value, ok := v2naiveUserLimiters.Load(user); ok {
			limiter := value.(*dynamicRateLimiter)
			limiter.mu.Lock()
			limiter.limiter = nil
			limiter.bytesPerSec = 0
			limiter.mu.Unlock()
		}
		v2naiveUserLimiters.Delete(user)
		return nil
	}

	bytesPerSec := speedLimit * 1000000 / 8
	if bytesPerSec <= 0 {
		v2naiveUserLimiters.Delete(user)
		return nil
	}

	value, _ := v2naiveUserLimiters.LoadOrStore(user, &dynamicRateLimiter{})
	limiter := value.(*dynamicRateLimiter)
	limiter.mu.Lock()
	if limiter.limiter == nil || limiter.bytesPerSec != bytesPerSec {
		limiter.limiter = rate.NewLimiter(rate.Limit(bytesPerSec), bytesPerSec)
		limiter.bytesPerSec = bytesPerSec
	}
	limiter.mu.Unlock()
	return limiter
}

func (d *dynamicRateLimiter) WaitN(n int) error {
	if d == nil || n <= 0 {
		return nil
	}
	d.mu.RLock()
	limiter := d.limiter
	burst := d.bytesPerSec
	d.mu.RUnlock()
	if limiter == nil || burst <= 0 {
		return nil
	}

	remaining := n
	for remaining > 0 {
		chunk := remaining
		if chunk > burst {
			chunk = burst
		}
		if err := limiter.WaitN(context.Background(), chunk); err != nil {
			return err
		}
		remaining -= chunk
	}
	return nil
}
