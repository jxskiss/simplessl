package server

import (
	"time"

	"github.com/jxskiss/gopkg/v2/fastrand"
)

var rand63n = fastrand.Int63n

var testOCSPDidUpdateLoop = func(next time.Duration, err error) {}

var ocspTimeNow = time.Now

func limitTTL(ttl time.Duration) int {
	if ttl <= 30*time.Second {
		return 10
	}
	if ttl <= time.Minute {
		return 30
	}
	var ttlSeconds int64 = 3600
	if ttl < time.Hour {
		ttlSeconds = int64(ttl.Seconds() * 0.8)
	}
	// add a little randomness to the TTL
	var jitter int64 = 60
	if ttlSeconds <= 2*jitter {
		jitter = ttlSeconds / 2
	}
	n := rand63n(jitter)
	if n < ttlSeconds {
		ttlSeconds -= n
	}
	return int(ttlSeconds)
}
