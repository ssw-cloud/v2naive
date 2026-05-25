package limiter

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juju/ratelimit"
	panel "github.com/ssw-cloud/v2naive/internal/panel"
)

type DynamicBucket struct {
	v atomic.Value
}

func NewDynamicBucket(rate int64) *DynamicBucket {
	b := ratelimit.NewBucketWithQuantum(time.Second, rate, rate)
	d := &DynamicBucket{}
	d.v.Store(b)
	return d
}

func (d *DynamicBucket) Get() *ratelimit.Bucket {
	bucket, _ := d.v.Load().(*ratelimit.Bucket)
	return bucket
}

func (d *DynamicBucket) Update(rate int64) {
	d.v.Store(ratelimit.NewBucketWithQuantum(time.Second, rate, rate))
}

type Limiter struct {
	NodeSpeedLimit int
	aliveMu        sync.RWMutex
	AliveList      map[int]int
	UserOnlineIP   *sync.Map
	OldUserOnline  *sync.Map
	UserLimitInfo  *sync.Map
	SpeedLimiter   *sync.Map
}

type UserLimitInfo struct {
	UID               int
	SpeedLimit        int
	DeviceLimit       int
	DynamicSpeedLimit int
	ExpireTime        int64
}

func New(users []panel.UserInfo, aliveList map[int]int) *Limiter {
	l := &Limiter{
		AliveList:     cloneAliveList(aliveList),
		UserOnlineIP:  new(sync.Map),
		OldUserOnline: new(sync.Map),
		UserLimitInfo: new(sync.Map),
		SpeedLimiter:  new(sync.Map),
	}
	for _, user := range users {
		l.UserLimitInfo.Store(user.Uuid, &UserLimitInfo{
			UID:         user.Id,
			SpeedLimit:  user.SpeedLimit,
			DeviceLimit: user.DeviceLimit,
		})
	}
	return l
}

func (l *Limiter) SetAliveList(alive map[int]int) {
	l.aliveMu.Lock()
	l.AliveList = cloneAliveList(alive)
	l.aliveMu.Unlock()
}

func (l *Limiter) UpdateUsers(added, deleted, modified []panel.UserInfo) {
	for _, user := range deleted {
		l.UserLimitInfo.Delete(user.Uuid)
		l.UserOnlineIP.Delete(user.Uuid)
		l.SpeedLimiter.Delete(user.Uuid)
		l.aliveMu.Lock()
		delete(l.AliveList, user.Id)
		l.aliveMu.Unlock()
	}
	for _, user := range modified {
		if value, ok := l.UserLimitInfo.Load(user.Uuid); ok {
			info := value.(*UserLimitInfo)
			info.SpeedLimit = user.SpeedLimit
			info.DeviceLimit = user.DeviceLimit
			l.UserLimitInfo.Store(user.Uuid, info)
			l.updateBucket(user.Uuid, determineSpeedLimit(l.NodeSpeedLimit, user.SpeedLimit))
		}
	}
	for _, user := range added {
		l.UserLimitInfo.Store(user.Uuid, &UserLimitInfo{
			UID:         user.Id,
			SpeedLimit:  user.SpeedLimit,
			DeviceLimit: user.DeviceLimit,
		})
		l.updateBucket(user.Uuid, determineSpeedLimit(l.NodeSpeedLimit, user.SpeedLimit))
	}
}

func (l *Limiter) updateBucket(uuid string, speedLimit int) {
	limit := int64(speedLimit) * 1000000 / 8
	if limit <= 0 {
		l.SpeedLimiter.Delete(uuid)
		return
	}
	if value, ok := l.SpeedLimiter.Load(uuid); ok {
		value.(*DynamicBucket).Update(limit)
		return
	}
	l.SpeedLimiter.Store(uuid, NewDynamicBucket(limit))
}

func (l *Limiter) CheckLimit(uuid, ip string) (*ratelimit.Bucket, bool) {
	ip = strings.TrimPrefix(ip, "::ffff:")
	infoValue, ok := l.UserLimitInfo.Load(uuid)
	if !ok {
		return nil, true
	}
	info := infoValue.(*UserLimitInfo)
	deviceLimit := info.DeviceLimit
	aliveIP := l.aliveCount(info.UID)

	ipMap := new(sync.Map)
	ipMap.Store(ip, info.UID)
	if value, loaded := l.UserOnlineIP.LoadOrStore(uuid, ipMap); loaded {
		oldMap := value.(*sync.Map)
		if _, seen := oldMap.LoadOrStore(ip, info.UID); !seen {
			if cachedUID, existed := l.OldUserOnline.Load(ip); existed {
				if cachedUID.(int) == info.UID {
					l.OldUserOnline.Delete(ip)
				}
			} else if deviceLimit > 0 && deviceLimit <= aliveIP {
				oldMap.Delete(ip)
				return nil, true
			}
		}
	} else if cachedUID, existed := l.OldUserOnline.Load(ip); existed {
		if cachedUID.(int) == info.UID {
			l.OldUserOnline.Delete(ip)
		}
	} else if deviceLimit > 0 && deviceLimit <= aliveIP {
		l.UserOnlineIP.Delete(uuid)
		return nil, true
	}

	speedLimit := determineSpeedLimit(l.NodeSpeedLimit, info.SpeedLimit)
	if speedLimit <= 0 {
		return nil, false
	}
	if value, ok := l.SpeedLimiter.Load(uuid); ok {
		return value.(*DynamicBucket).Get(), false
	}
	bucket := NewDynamicBucket(int64(speedLimit) * 1000000 / 8)
	l.SpeedLimiter.Store(uuid, bucket)
	return bucket.Get(), false
}

func (l *Limiter) GetOnlineDevice() []panel.OnlineUser {
	var users []panel.OnlineUser
	l.OldUserOnline = new(sync.Map)
	l.UserOnlineIP.Range(func(key, value any) bool {
		ipMap := value.(*sync.Map)
		ipMap.Range(func(ip, uid any) bool {
			l.OldUserOnline.Store(ip.(string), uid.(int))
			users = append(users, panel.OnlineUser{UID: uid.(int), IP: ip.(string)})
			return true
		})
		l.UserOnlineIP.Delete(key)
		return true
	})
	return users
}

func determineSpeedLimit(limit1, limit2 int) int {
	if limit1 == 0 || limit2 == 0 {
		if limit1 > limit2 {
			return limit1
		}
		if limit1 < limit2 {
			return limit2
		}
		return 0
	}
	if limit1 > limit2 {
		return limit2
	}
	if limit1 < limit2 {
		return limit1
	}
	return limit1
}

func (l *Limiter) aliveCount(uid int) int {
	l.aliveMu.RLock()
	defer l.aliveMu.RUnlock()
	return l.AliveList[uid]
}

func cloneAliveList(in map[int]int) map[int]int {
	out := make(map[int]int, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
