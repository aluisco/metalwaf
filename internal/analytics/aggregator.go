// Package analytics provides in-memory aggregation for request metrics and
// a non-blocking collector that persists request logs to the database.
package analytics

import (
	"sync"
	"time"
)

const bucketCount = 60 // one slot per minute → last 60 minutes of history

type bucket struct {
	minute  int64 // unix_timestamp / 60
	total   int64
	blocked int64
}

// Aggregator maintains a per-minute ring buffer of request metrics.
// The zero value is ready to use and safe for concurrent access.
type Aggregator struct {
	mu  sync.RWMutex
	buf [bucketCount]bucket
}

// Record updates the current-minute bucket with one request.
func (a *Aggregator) Record(blocked bool) {
	now := time.Now().Unix() / 60
	idx := now % bucketCount

	a.mu.Lock()
	b := &a.buf[idx]
	if b.minute != now {
		*b = bucket{minute: now}
	}
	b.total++
	if blocked {
		b.blocked++
	}
	a.mu.Unlock()
}

// MinuteStat is one per-minute data point in the traffic timeline.
type MinuteStat struct {
	UnixMinute int64 `json:"unix_minute"` // UTC unix timestamp ÷ 60
	Total      int64 `json:"total"`
	Blocked    int64 `json:"blocked"`
}

// Snapshot returns stats for the last n minutes, oldest first, current last.
// n is clamped to [1, bucketCount].
func (a *Aggregator) Snapshot(n int) []MinuteStat {
	if n < 1 {
		n = 1
	}
	if n > bucketCount {
		n = bucketCount
	}
	now := time.Now().Unix() / 60

	a.mu.RLock()
	defer a.mu.RUnlock()

	out := make([]MinuteStat, n)
	for i := 0; i < n; i++ {
		m := now - int64(n-1-i) // oldest → newest
		s := MinuteStat{UnixMinute: m}
		b := a.buf[m%bucketCount]
		if b.minute == m {
			s.Total = b.total
			s.Blocked = b.blocked
		}
		out[i] = s
	}
	return out
}

// LastMinute returns total and blocked counts for the previous completed minute.
func (a *Aggregator) LastMinute() (total, blocked int64) {
	prev := time.Now().Unix()/60 - 1
	a.mu.RLock()
	b := a.buf[prev%bucketCount]
	a.mu.RUnlock()
	if b.minute == prev {
		return b.total, b.blocked
	}
	return 0, 0
}

// BlockedLastMinute is a convenience wrapper over LastMinute.
func (a *Aggregator) BlockedLastMinute() int64 {
	_, blocked := a.LastMinute()
	return blocked
}
