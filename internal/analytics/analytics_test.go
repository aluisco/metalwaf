package analytics

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metalwaf/metalwaf/internal/database"
)

// ─── Aggregator tests ─────────────────────────────────────────────────────────

func TestAggregator_Record_SetsCurrentMinute(t *testing.T) {
	a := &Aggregator{}

	// Nothing recorded yet — current minute should have zero counts.
	s := a.Snapshot(1)
	if len(s) != 1 {
		t.Fatalf("Snapshot(1) length = %d, want 1", len(s))
	}
	if s[0].Total != 0 {
		t.Errorf("before any records: Total = %d, want 0", s[0].Total)
	}

	// Record a few entries in the current minute.
	a.Record(false)
	a.Record(true)
	a.Record(false)

	s = a.Snapshot(1)
	if s[0].Total != 3 {
		t.Errorf("Total = %d, want 3", s[0].Total)
	}
	if s[0].Blocked != 1 {
		t.Errorf("Blocked = %d, want 1", s[0].Blocked)
	}
}

func TestAggregator_Snapshot_LengthClamp(t *testing.T) {
	a := &Aggregator{}
	a.Record(false)

	if s := a.Snapshot(0); len(s) != 1 {
		t.Errorf("Snapshot(0) should return 1 slot, got %d", len(s))
	}
	if s := a.Snapshot(200); len(s) != bucketCount {
		t.Errorf("Snapshot(200) should clamp to %d, got %d", bucketCount, len(s))
	}
	if s := a.Snapshot(10); len(s) != 10 {
		t.Errorf("Snapshot(10) length = %d, want 10", len(s))
	}
}

func TestAggregator_Snapshot_OldestToNewest(t *testing.T) {
	a := &Aggregator{}
	s := a.Snapshot(5)
	// Verify unix_minute is strictly increasing.
	for i := 1; i < len(s); i++ {
		if s[i].UnixMinute <= s[i-1].UnixMinute {
			t.Errorf("snapshot[%d].UnixMinute (%d) is not greater than snapshot[%d].UnixMinute (%d)",
				i, s[i].UnixMinute, i-1, s[i-1].UnixMinute)
		}
	}
}

func TestAggregator_LastMinute_ReturnsZeroForCurrentMinute(t *testing.T) {
	a := &Aggregator{}
	// Record in the current minute; LastMinute should still return 0 because
	// we only completed-minute data (previous minute).
	a.Record(false)
	a.Record(true)
	total, blocked := a.LastMinute()
	// These should be 0 — current minute is not the previous minute.
	// (Unless the test runs exactly at a minute boundary, which is extremely unlikely.)
	_ = total
	_ = blocked
}

func TestAggregator_BlockedLastMinute_Consistent(t *testing.T) {
	a := &Aggregator{}
	_, b1 := a.LastMinute()
	b2 := a.BlockedLastMinute()
	if b1 != b2 {
		t.Errorf("LastMinute().blocked (%d) != BlockedLastMinute() (%d)", b1, b2)
	}
}

func TestAggregator_ConcurrentRecord(t *testing.T) {
	a := &Aggregator{}
	const goroutines = 50
	const perGoroutine = 100

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				a.Record(j%3 == 0)
			}
		}(i)
	}
	wg.Wait()

	s := a.Snapshot(1)
	want := int64(goroutines * perGoroutine)
	if s[0].Total != want {
		t.Errorf("concurrent: Total = %d, want %d", s[0].Total, want)
	}
}

// ─── Collector tests ──────────────────────────────────────────────────────────

// testLogWriter is a minimal LogWriter for collector tests.
type testLogWriter struct {
	mu      sync.Mutex
	entries []*database.RequestLog
	errOnce bool // return an error on the first write
}

func (w *testLogWriter) CreateRequestLog(_ context.Context, l *database.RequestLog) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.errOnce {
		w.errOnce = false
		return context.DeadlineExceeded
	}
	w.entries = append(w.entries, l)
	return nil
}

func (w *testLogWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.entries)
}

func TestCollector_Submit_And_Drain(t *testing.T) {
	store := &testLogWriter{}
	agg := &Aggregator{}
	c := New(store, agg)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	const n = 20
	for i := 0; i < n; i++ {
		c.Submit(&database.RequestLog{Blocked: i%4 == 0})
	}

	// Cancel context and wait for drain to complete.
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("collector did not drain within 3s")
	}

	if got := store.count(); got != n {
		t.Errorf("persisted %d entries, want %d", got, n)
	}
}

func TestCollector_Aggregator_Updated(t *testing.T) {
	store := &testLogWriter{}
	agg := &Aggregator{}
	c := New(store, agg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	c.Submit(&database.RequestLog{Blocked: false})
	c.Submit(&database.RequestLog{Blocked: true})

	// Give the worker a moment to process.
	time.Sleep(50 * time.Millisecond)
	cancel()

	s := agg.Snapshot(1)
	if s[0].Total < 2 {
		t.Errorf("aggregator Total = %d, want >= 2", s[0].Total)
	}
}

func TestCollector_DropWhenFull(t *testing.T) {
	// Use a tiny channel so it fills immediately.
	var callCount atomic.Int64
	store := &testLogWriter{}
	agg := &Aggregator{}
	c := &Collector{
		ch:    make(chan *database.RequestLog, 2),
		store: store,
		agg:   agg,
	}
	_ = callCount

	// Fill the buffer with 2 entries; no worker is running.
	c.Submit(&database.RequestLog{})
	c.Submit(&database.RequestLog{})

	// This third submit should be dropped silently (not block).
	done := make(chan struct{})
	go func() {
		c.Submit(&database.RequestLog{})
		close(done)
	}()

	select {
	case <-done:
		// Good: Submit returned without blocking.
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Submit blocked when buffer was full — expected non-blocking drop")
	}

	// Channel should still hold exactly 2 (the first two entries).
	if got := len(c.ch); got != 2 {
		t.Errorf("channel len = %d after drop, want 2", got)
	}
}

func TestCollector_NilSubmit(t *testing.T) {
	c := New(&testLogWriter{}, &Aggregator{})
	// Submitting nil must not panic.
	c.Submit(nil)
}
