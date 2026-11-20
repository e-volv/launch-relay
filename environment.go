package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/e-volv/logs-go/flags"
)

// refreshInterval is how often the relay re-checks upstream. A conditional
// request that comes back 304 costs no payload.
const refreshInterval = 30 * time.Second

// refreshTimeout bounds one upstream fetch. Refreshes never run on a
// requester's context: a client that hangs up must not abort the fetch every
// other client is waiting on.
const refreshTimeout = 10 * time.Second

// Environment is one upstream e-volv environment: its server key, the client
// keys the relay accepts for it, the last ruleset it fetched and the exposures
// waiting to be forwarded with its key.
type Environment struct {
	ID           string
	ServerKey    string
	ClientKeys   []string
	Upstream     string
	SnapshotPath string
	HTTP         *http.Client

	exposures ExposureBuffer

	refreshMu sync.Mutex // one upstream fetch at a time

	mu            sync.RWMutex
	snapshot      []byte
	etag          string
	environmentID string
	updatedAt     time.Time
	stale         bool
	lastAttempt   time.Time

	subsMu sync.Mutex
	subs   map[chan struct{}]struct{}
}

type snapshotEnvelope struct {
	Ruleset   json.RawMessage `json:"ruleset"`
	Etag      string          `json:"etag"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

// Load reads the last snapshot written to disk. It is served as stale until
// upstream confirms or replaces it.
func (e *Environment) Load() error {
	body, err := os.ReadFile(e.SnapshotPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var envelope snapshotEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.snapshot = envelope.Ruleset
	e.etag = envelope.Etag
	e.environmentID = rulesetEnvironmentID(envelope.Ruleset)
	e.updatedAt = envelope.UpdatedAt
	e.stale = true
	return nil
}

// Run refreshes from upstream until ctx is cancelled.
func (e *Environment) Run(ctx context.Context) {
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for {
		_ = e.Refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Refresh fetches the ruleset from upstream once. It keeps the new ruleset in
// memory even when the disk snapshot cannot be written; the write error is
// still returned so the caller can log it.
func (e *Environment) Refresh(parent context.Context) error {
	e.refreshMu.Lock()
	defer e.refreshMu.Unlock()
	return e.refreshLocked(parent)
}

func (e *Environment) refreshLocked(parent context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), refreshTimeout)
	defer cancel()

	e.mu.Lock()
	e.lastAttempt = time.Now()
	etag := e.etag
	e.mu.Unlock()

	url := e.Upstream + "/api/public/v1/flags/bootstrap?v=" + strconv.Itoa(flags.RulesetVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "Bearer "+e.ServerKey)
	req.Header.Set("user-agent", "e-volv-launch-relay")
	if etag != "" {
		req.Header.Set("if-none-match", `"`+etag+`"`)
	}
	res, err := e.HTTP.Do(req)
	if err != nil {
		e.markStale()
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotModified {
		e.mu.Lock()
		e.stale = false
		e.updatedAt = time.Now()
		e.mu.Unlock()
		return nil
	}
	if res.StatusCode != http.StatusOK {
		e.markStale()
		return fmt.Errorf("upstream returned %s", res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		e.markStale()
		return err
	}
	var metadata struct {
		Etag          string `json:"etag"`
		EnvironmentID string `json:"environmentId"`
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		e.markStale()
		return err
	}
	now := time.Now()
	e.mu.Lock()
	changed := metadata.Etag != e.etag || len(e.snapshot) == 0
	e.snapshot = body
	e.etag = metadata.Etag
	e.environmentID = metadata.EnvironmentID
	e.updatedAt = now
	e.stale = false
	e.mu.Unlock()
	if changed {
		e.notify()
	}
	return e.persist(snapshotEnvelope{Ruleset: body, Etag: metadata.Etag, UpdatedAt: now})
}

func (e *Environment) persist(envelope snapshotEnvelope) error {
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.SnapshotPath), 0o700); err != nil {
		return err
	}
	tmp := e.SnapshotPath + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.SnapshotPath)
}

func (e *Environment) markStale() {
	e.mu.Lock()
	e.stale = true
	e.mu.Unlock()
}

// Snapshot returns the ruleset the relay holds. It only goes upstream itself
// when it holds nothing; otherwise the background refresh keeps it current.
func (e *Environment) Snapshot(ctx context.Context) ([]byte, string, bool, time.Time, error) {
	if !e.hasSnapshot() {
		e.refreshMu.Lock()
		e.mu.RLock()
		due := len(e.snapshot) == 0 && time.Since(e.lastAttempt) >= 5*time.Second
		e.mu.RUnlock()
		if due {
			_ = e.refreshLocked(ctx)
		}
		e.refreshMu.Unlock()
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.snapshot) == 0 {
		return nil, "", true, time.Time{}, errors.New("no snapshot and upstream unavailable")
	}
	return e.snapshot, e.etag, e.stale, e.updatedAt, nil
}

func (e *Environment) hasSnapshot() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.snapshot) > 0
}

// StreamID is the environment id the stream and evaluated responses carry:
// the upstream ruleset's own id, falling back to the configured name.
func (e *Environment) StreamID() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.environmentID != "" {
		return e.environmentID
	}
	return e.ID
}

// Healthy reports staleness and age without going upstream.
func (e *Environment) Healthy() (bool, int64) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.snapshot) == 0 {
		return true, 0
	}
	age := int64(0)
	if !e.updatedAt.IsZero() {
		age = int64(time.Since(e.updatedAt).Seconds())
	}
	return e.stale, age
}

// Subscribe returns a channel that receives a signal whenever a refresh
// replaces the ruleset with one carrying a different etag.
func (e *Environment) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	e.subsMu.Lock()
	if e.subs == nil {
		e.subs = make(map[chan struct{}]struct{})
	}
	e.subs[ch] = struct{}{}
	e.subsMu.Unlock()
	return ch, func() {
		e.subsMu.Lock()
		delete(e.subs, ch)
		e.subsMu.Unlock()
	}
}

func (e *Environment) notify() {
	e.subsMu.Lock()
	defer e.subsMu.Unlock()
	for ch := range e.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func rulesetEnvironmentID(body []byte) string {
	var metadata struct {
		EnvironmentID string `json:"environmentId"`
	}
	_ = json.Unmarshal(body, &metadata)
	return metadata.EnvironmentID
}

func upstreamBase(value string) string {
	return strings.TrimRight(value, "/")
}
