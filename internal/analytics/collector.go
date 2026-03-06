package analytics

import (
	"context"
	"log/slog"

	"github.com/metalwaf/metalwaf/internal/database"
)

// bufSize is the collector's channel capacity.
// At 10 k req/s a 4096-slot buffer gives roughly 400 ms of head-room before
// entries are dropped, which is far more than any reasonable drain latency.
const bufSize = 4096

// LogWriter is the subset of database.Store required by the Collector.
// Using a narrow interface keeps tests simple and avoids coupling the
// analytics package to the full Store.
type LogWriter interface {
	CreateRequestLog(ctx context.Context, l *database.RequestLog) error
}

// Collector is a non-blocking, buffered ingestion pipeline for request logs.
// The proxy calls Submit on the hot path; a single background worker drains
// the channel, updates the Aggregator, and persists entries to the database.
// When the buffer is full the entry is dropped with a warning rather than
// blocking the caller.
type Collector struct {
	ch    chan *database.RequestLog
	store LogWriter
	agg   *Aggregator
}

// New returns a Collector. Call Run in a goroutine to start the background worker.
func New(store LogWriter, agg *Aggregator) *Collector {
	return &Collector{
		ch:    make(chan *database.RequestLog, bufSize),
		store: store,
		agg:   agg,
	}
}

// Submit enqueues l for asynchronous persistence. It never blocks the caller.
func (c *Collector) Submit(l *database.RequestLog) {
	if l == nil {
		return
	}
	select {
	case c.ch <- l:
	default:
		slog.Warn("analytics: collector buffer full — request log dropped")
	}
}

// Run drives the worker loop until ctx is cancelled.
// On shutdown it drains the remaining buffer before returning so no entries
// are lost during a graceful stop.
func (c *Collector) Run(ctx context.Context) {
	for {
		select {
		case l := <-c.ch:
			c.process(ctx, l)
		case <-ctx.Done():
			// Drain with a background context so the timeout doesn't cut short
			// the final writes.
			bg := context.Background()
			for {
				select {
				case l := <-c.ch:
					c.process(bg, l)
				default:
					return
				}
			}
		}
	}
}

func (c *Collector) process(ctx context.Context, l *database.RequestLog) {
	if c.agg != nil {
		c.agg.Record(l.Blocked)
	}
	if err := c.store.CreateRequestLog(ctx, l); err != nil {
		slog.Warn("analytics: failed to persist request log", "error", err)
	}
}
