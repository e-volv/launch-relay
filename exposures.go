package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// exposureCap is the most rows one environment's buffer holds. Past it the
// oldest rows are dropped: an exposure is at worst a gap in a chart, and the
// newest rows describe what users are seeing now.
const exposureCap = 10_000

// exposureBatch is the upstream's per-request limit (IngestExposuresDto).
const exposureBatch = 1000

// ExposureBuffer holds one environment's exposures until they are forwarded
// with that environment's server key.
type ExposureBuffer struct {
	mu    sync.Mutex
	items []json.RawMessage
}

func (b *ExposureBuffer) Add(batch []json.RawMessage) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items = append(b.items, batch...)
	b.trimLocked()
}

func (b *ExposureBuffer) Drain(limit int) []json.RawMessage {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) == 0 {
		return nil
	}
	if limit > len(b.items) {
		limit = len(b.items)
	}
	out := append([]json.RawMessage(nil), b.items[:limit]...)
	b.items = append([]json.RawMessage(nil), b.items[limit:]...)
	return out
}

// Requeue puts a batch that failed to send back in front of the rows that
// arrived since. The batch is older, so it is what goes first past the cap.
func (b *ExposureBuffer) Requeue(batch []json.RawMessage) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items = append(append([]json.RawMessage(nil), batch...), b.items...)
	b.trimLocked()
}

func (b *ExposureBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

func (b *ExposureBuffer) trimLocked() {
	if len(b.items) > exposureCap {
		b.items = append([]json.RawMessage(nil), b.items[len(b.items)-exposureCap:]...)
	}
}

func (r *Relay) flushExposures(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, environment := range r.environments {
				environment.flushExposures(ctx)
			}
		}
	}
}

// flushExposures forwards this environment's buffer in batches until it is
// empty or upstream refuses one, which is requeued for the next tick.
func (e *Environment) flushExposures(ctx context.Context) {
	for {
		batch := e.exposures.Drain(exposureBatch)
		if len(batch) == 0 {
			return
		}
		switch e.sendExposures(ctx, batch) {
		case sendRetry:
			e.exposures.Requeue(batch)
			return
		case sendRejected:
			// Upstream refused the rows themselves. Sending them again
			// would fail the same way and hold up every row behind them.
			continue
		}
	}
}

type sendResult int

const (
	sendOK sendResult = iota
	sendRetry
	sendRejected
)

func (e *Environment) sendExposures(ctx context.Context, batch []json.RawMessage) sendResult {
	body, err := json.Marshal(map[string]any{"exposures": batch})
	if err != nil {
		return sendRejected
	}
	reqCtx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, e.Upstream+"/api/public/v1/flags/exposures", bytes.NewReader(body))
	if err != nil {
		return sendRetry
	}
	req.Header.Set("authorization", "Bearer "+e.ServerKey)
	req.Header.Set("content-type", "application/json")
	req.Header.Set("user-agent", "e-volv-launch-relay")
	res, err := e.HTTP.Do(req)
	if err != nil {
		return sendRetry
	}
	_ = res.Body.Close()
	switch {
	case res.StatusCode < 300:
		return sendOK
	case res.StatusCode == http.StatusBadRequest || res.StatusCode == http.StatusRequestEntityTooLarge:
		return sendRejected
	default:
		return sendRetry
	}
}
