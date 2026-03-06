package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metalwaf/metalwaf/internal/database"
)

const (
	healthCheckInterval = 10 * time.Second
	healthCheckTimeout  = 3 * time.Second
	maxConsecFails      = 3
)

// backend holds the URL and health state for a single upstream server.
type backend struct {
	raw      string // original URL string, used for logging
	url      *url.URL
	weight   int
	healthy  atomic.Bool
	failures atomic.Int32
}

func newBackend(u *database.Upstream) (*backend, error) {
	parsed, err := url.Parse(u.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL %q: %w", u.URL, err)
	}
	b := &backend{raw: u.URL, url: parsed, weight: u.Weight}
	b.healthy.Store(true)
	return b, nil
}

// UpstreamPool manages a set of backends for one site with weighted
// round-robin selection and automatic health checking.
type UpstreamPool struct {
	mu       sync.RWMutex
	backends []*backend
	counter  atomic.Int64 // round-robin counter
}

// NewPool builds an UpstreamPool from a list of database upstreams.
// Disabled upstreams are excluded. Returns an empty (valid) pool if the list
// is empty or all entries are disabled.
func NewPool(upstreams []*database.Upstream) (*UpstreamPool, error) {
	pool := &UpstreamPool{}
	for _, u := range upstreams {
		if !u.Enabled {
			continue
		}
		b, err := newBackend(u)
		if err != nil {
			return nil, err
		}
		pool.backends = append(pool.backends, b)
	}
	return pool, nil
}

// Next returns the URL of the next healthy backend using weighted round-robin.
// Returns nil if no healthy backends are available.
func (p *UpstreamPool) Next() *url.URL {
	p.mu.RLock()
	backends := p.backends
	p.mu.RUnlock()

	// Build a candidate list: healthy backends repeated by their weight.
	var candidates []*backend
	for _, b := range backends {
		if b.healthy.Load() {
			for range b.weight {
				candidates = append(candidates, b)
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	idx := int(p.counter.Add(1)-1) % len(candidates)
	return candidates[idx].url
}

// StartHealthChecks launches a background goroutine that periodically probes
// all backends with an HTTP HEAD request and updates their healthy flag.
// The goroutine stops when ctx is cancelled.
func (p *UpstreamPool) StartHealthChecks(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(healthCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.mu.RLock()
				backends := make([]*backend, len(p.backends))
				copy(backends, p.backends)
				p.mu.RUnlock()
				for _, b := range backends {
					go p.checkOne(ctx, b)
				}
			}
		}
	}()
}

func (p *UpstreamPool) checkOne(ctx context.Context, b *backend) {
	probeURL := b.url.Scheme + "://" + b.url.Host + "/"

	reqCtx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodHead, probeURL, nil)
	if err != nil {
		p.recordFailure(b)
		return
	}

	client := &http.Client{Timeout: healthCheckTimeout}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode >= 500 {
		p.recordFailure(b)
		return
	}

	// Recovery: backend responded successfully.
	wasUnhealthy := !b.healthy.Load()
	b.failures.Store(0)
	b.healthy.Store(true)
	if wasUnhealthy {
		slog.Info("proxy: upstream recovered", "url", b.raw)
	}
}

func (p *UpstreamPool) recordFailure(b *backend) {
	n := b.failures.Add(1)
	if int(n) >= maxConsecFails && b.healthy.Load() {
		b.healthy.Store(false)
		slog.Warn("proxy: upstream marked unhealthy",
			"url", b.raw,
			"consecutive_failures", n,
		)
	}
}
