package proxy

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultRPS   = 100.0           // requests per second allowed per IP
	defaultBurst = 200             // burst capacity per IP
	staleAfter   = 5 * time.Minute // remove entries not seen for this long
)

type ipLimiter struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// rateLimiter is a per-client-IP token bucket rate limiter.
// A separate bucket is maintained for each source IP address.
type rateLimiter struct {
	mu      sync.Mutex
	clients map[string]*ipLimiter
	rps     float64
	burst   int
}

func newRateLimiter(rps float64, burst int) *rateLimiter {
	rl := &rateLimiter{
		clients: make(map[string]*ipLimiter),
		rps:     rps,
		burst:   burst,
	}
	go rl.cleanup()
	return rl
}

// allow returns true if the given IP is within its rate limit.
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	cl, ok := rl.clients[ip]
	if !ok {
		cl = &ipLimiter{lim: rate.NewLimiter(rate.Limit(rl.rps), rl.burst)}
		rl.clients[ip] = cl
	}
	cl.lastSeen = time.Now()
	allowed := cl.lim.Allow()
	rl.mu.Unlock()
	return allowed
}

// cleanup periodically removes stale entries to prevent unbounded memory growth.
func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(staleAfter)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		for ip, cl := range rl.clients {
			if time.Since(cl.lastSeen) > staleAfter {
				delete(rl.clients, ip)
			}
		}
		rl.mu.Unlock()
	}
}
