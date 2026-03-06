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
	if rps <= 0 {
		rps = defaultRPS
	}
	if burst <= 0 {
		burst = defaultBurst
	}
	rl := &rateLimiter{
		clients: make(map[string]*ipLimiter),
		rps:     rps,
		burst:   burst,
	}
	go rl.cleanup()
	return rl
}

// updateLimits replaces the rate/burst values; existing buckets are reset.
func (rl *rateLimiter) updateLimits(rps float64, burst int) {
	if rps <= 0 {
		rps = defaultRPS
	}
	if burst <= 0 {
		burst = defaultBurst
	}
	rl.mu.Lock()
	rl.rps = rps
	rl.burst = burst
	rl.clients = make(map[string]*ipLimiter) // reset all buckets
	rl.mu.Unlock()
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

// rateLimiterMap manages a per-site map of rate limiters.
type rateLimiterMap struct {
	mu       sync.RWMutex
	limiters map[string]*rateLimiter // siteID → limiter
}

func newRateLimiterMap() *rateLimiterMap {
	return &rateLimiterMap{limiters: make(map[string]*rateLimiter)}
}

// rebuild replaces the entire map in one atomic swap.
// entries is a map of siteID → (rps, burst).
func (m *rateLimiterMap) rebuild(entries map[string][2]float64) {
	newMap := make(map[string]*rateLimiter, len(entries))
	for siteID, cfg := range entries {
		newMap[siteID] = newRateLimiter(cfg[0], int(cfg[1]))
	}
	m.mu.Lock()
	m.limiters = newMap
	m.mu.Unlock()
}

// allow checks the per-site limiter for siteID and client IP.
// Returns true (allow) if no site-specific limiter is configured.
func (m *rateLimiterMap) allow(siteID, clientIP string) bool {
	m.mu.RLock()
	rl, ok := m.limiters[siteID]
	m.mu.RUnlock()
	if !ok {
		return true // no per-site limit configured → pass
	}
	return rl.allow(clientIP)
}
