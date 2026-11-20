package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/e-volv/logs-go/flags"
)

// heartbeatInterval matches the backend stream; the SDK's dead-connection
// timeout is 60 s.
const heartbeatInterval = 25 * time.Second

type Relay struct {
	environments []*Environment
	cancel       context.CancelFunc
}

// NewFromEnvironment builds a relay from its environment variables:
//
//	EVOLVE_RELAY_KEYS         production=evk_...,staging=evk_...   (server keys, one per environment)
//	EVOLVE_RELAY_CLIENT_KEYS  production=evk_pub_a|evk_pub_b       (client keys the relay accepts, per environment)
//	EVOLVE_RELAY_DATA_DIR     where snapshots are written
//	EVOLVE_RELAY_UPSTREAM     default https://api.e-volv.io
func NewFromEnvironment() (*Relay, error) {
	dataDir := os.Getenv("EVOLVE_RELAY_DATA_DIR")
	if dataDir == "" {
		dataDir = os.TempDir()
	}
	upstream := os.Getenv("EVOLVE_RELAY_UPSTREAM")
	if upstream == "" {
		upstream = "https://api.e-volv.io"
	}
	environments, err := parseEnvironments(os.Getenv("EVOLVE_RELAY_KEYS"), os.Getenv("EVOLVE_RELAY_CLIENT_KEYS"), upstreamBase(upstream), dataDir)
	if err != nil {
		return nil, err
	}
	relay := &Relay{environments: environments}
	for _, environment := range environments {
		if err := environment.Load(); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	relay.cancel = cancel
	relay.start(ctx)
	return relay, nil
}

func (r *Relay) start(ctx context.Context) {
	for _, environment := range r.environments {
		go environment.Run(ctx)
	}
	go r.flushExposures(ctx)
}

func parseEnvironments(serverKeys, clientKeys, upstream, dataDir string) ([]*Environment, error) {
	var environments []*Environment
	byID := map[string]*Environment{}
	for _, item := range strings.Split(serverKeys, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		id, key, ok := strings.Cut(item, "=")
		id, key = strings.TrimSpace(id), strings.TrimSpace(key)
		if !ok || id == "" || key == "" {
			return nil, fmt.Errorf("EVOLVE_RELAY_KEYS entries must be <environment>=<server key>")
		}
		if strings.HasPrefix(key, "evk_pub_") {
			return nil, fmt.Errorf("EVOLVE_RELAY_KEYS %q holds a client key; it needs a server key", id)
		}
		if byID[id] != nil {
			return nil, fmt.Errorf("EVOLVE_RELAY_KEYS names environment %q twice", id)
		}
		digest := sha256.Sum256([]byte(key))
		environment := &Environment{
			ID: id, ServerKey: key, Upstream: upstream,
			SnapshotPath: filepath.Join(dataDir, "relay-"+hex.EncodeToString(digest[:8])+".json"),
			HTTP:         &http.Client{Timeout: refreshTimeout},
		}
		byID[id] = environment
		environments = append(environments, environment)
	}
	if len(environments) == 0 {
		return nil, fmt.Errorf("EVOLVE_RELAY_KEYS is required")
	}
	for _, item := range strings.Split(clientKeys, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		id, keys, ok := strings.Cut(item, "=")
		environment := byID[strings.TrimSpace(id)]
		if !ok || environment == nil {
			return nil, fmt.Errorf("EVOLVE_RELAY_CLIENT_KEYS entry %q does not name an environment in EVOLVE_RELAY_KEYS", strings.TrimSpace(id))
		}
		for _, key := range strings.Split(keys, "|") {
			key = strings.TrimSpace(key)
			if !strings.HasPrefix(key, "evk_pub_") {
				return nil, fmt.Errorf("EVOLVE_RELAY_CLIENT_KEYS for %q must be evk_pub_ keys", environment.ID)
			}
			environment.ClientKeys = append(environment.ClientKeys, key)
		}
	}
	return environments, nil
}

func (r *Relay) Close() { r.cancel() }

func (r *Relay) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", r.health)
	mux.HandleFunc("/bootstrap", r.bootstrap)
	mux.HandleFunc("/stream", r.stream)
	mux.HandleFunc("/exposures", r.receiveExposures)
	return mux
}

func bearer(req *http.Request) string {
	header := req.Header.Get("authorization")
	if len(header) > 7 && strings.EqualFold(header[:7], "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}

// authenticate finds the environment a key belongs to. Every configured key is
// compared in constant time and the scan never stops early, so response
// timing says nothing about how close a guess was.
func (r *Relay) authenticate(key string) (*Environment, bool) {
	var found *Environment
	client := false
	if key == "" {
		return nil, false
	}
	candidate := []byte(key)
	for _, environment := range r.environments {
		if subtle.ConstantTimeCompare(candidate, []byte(environment.ServerKey)) == 1 {
			found, client = environment, false
		}
		for _, clientKey := range environment.ClientKeys {
			if subtle.ConstantTimeCompare(candidate, []byte(clientKey)) == 1 {
				found, client = environment, true
			}
		}
	}
	return found, client
}

func unauthorized(w http.ResponseWriter) {
	writeJSON(w, http.StatusUnauthorized, map[string]any{"statusCode": 401, "message": "Invalid API key"})
}

// health is unauthenticated for load balancers. With a valid key it reports
// that key's environment; without one, the worst of all of them.
func (r *Relay) health(w http.ResponseWriter, req *http.Request) {
	targets := r.environments
	if environment, _ := r.authenticate(bearer(req)); environment != nil {
		targets = []*Environment{environment}
	}
	stale, age := false, int64(0)
	for _, environment := range targets {
		s, a := environment.Healthy()
		stale = stale || s
		if a > age {
			age = a
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stale": stale, "ageSeconds": age})
}

func (r *Relay) bootstrap(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	environment, isClient := r.authenticate(bearer(req))
	if environment == nil {
		unauthorized(w)
		return
	}
	w.Header().Set("cache-control", "no-store")
	snapshot, etag, _, _, err := environment.Snapshot(req.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": err.Error()})
		return
	}
	if isClient {
		r.evaluate(w, req, environment, snapshot, etag)
		return
	}
	if etag != "" {
		w.Header().Set("etag", `"`+etag+`"`)
		if strings.ReplaceAll(req.Header.Get("if-none-match"), `"`, "") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	w.Header().Set("content-type", "application/json")
	_, _ = w.Write(snapshot)
}

// flagVisibility reads the two definition fields the Go kernel port does not
// carry. Absent means false: a flag is server-side by default.
type flagVisibility struct {
	Flags map[string]struct {
		Definition struct {
			ClientSideAvailable bool `json:"clientSideAvailable"`
			MobileAvailable     bool `json:"mobileAvailable"`
		} `json:"definition"`
	} `json:"flags"`
}

// visibleFlags is the backend's filterFlagsForCaller: a web caller sees flags
// with clientSideAvailable, a mobile caller (x-evolve-app-id) flags with
// mobileAvailable.
func visibleFlags(snapshot []byte, mobile bool) (map[string]bool, error) {
	var visibility flagVisibility
	if err := json.Unmarshal(snapshot, &visibility); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for key, flag := range visibility.Flags {
		if (!mobile && flag.Definition.ClientSideAvailable) || (mobile && flag.Definition.MobileAvailable) {
			out[key] = true
		}
	}
	return out, nil
}

// evaluate answers a client key with values, never rules, the way
// RulesetService.evaluatedFor does.
func (r *Relay) evaluate(w http.ResponseWriter, req *http.Request, environment *Environment, snapshot []byte, etag string) {
	var ruleset flags.Ruleset
	if err := json.Unmarshal(snapshot, &ruleset); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"message": "invalid snapshot"})
		return
	}
	_, mobile := req.Header[http.CanonicalHeaderKey("x-evolve-app-id")]
	visible, err := visibleFlags(snapshot, mobile)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"message": "invalid snapshot"})
		return
	}
	for key := range ruleset.Flags {
		if !visible[key] {
			delete(ruleset.Flags, key)
		}
	}
	contextValues := parseContext(req.URL.Query().Get("context"))
	values := make(map[string]flags.Evaluation, len(ruleset.Flags))
	for key := range ruleset.Flags {
		// A null fallback, as the kernel's evaluateAll uses: a flag with no
		// variants evaluates to null rather than panicking the relay.
		values[key] = flags.Evaluate(&ruleset, key, nil, contextValues, nil)
	}
	environmentID := ruleset.EnvironmentID
	if environmentID == "" {
		environmentID = environment.StreamID()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rulesetVersion": flags.RulesetVersion,
		"environmentId":  environmentID,
		"etag":           etag,
		"flags":          values,
	})
}

// parseContext mirrors the backend: bounded, object-only, never throwing. A
// malformed context becomes an empty one.
func parseContext(raw string) flags.Context {
	values := flags.Context{}
	if raw == "" || len(raw) > 4096 {
		return values
	}
	var parsed map[string]any
	if json.Unmarshal([]byte(raw), &parsed) != nil || parsed == nil {
		return values
	}
	return flags.Context(parsed)
}

// stream follows the backend's: a `ruleset` hello carrying the current etag,
// a `ruleset` event whenever a refresh brings a ruleset with a new etag, and a
// heartbeat every 25 s. Changes reach the relay by polling upstream every
// refreshInterval, so an event can lag the dashboard by up to that long.
func (r *Relay) stream(w http.ResponseWriter, req *http.Request) {
	environment, isClient := r.authenticate(bearer(req))
	if environment == nil {
		unauthorized(w)
		return
	}
	if isClient {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"statusCode": 403,
			"message":    "A client (evk_pub_) key cannot open the flags stream. Client SDKs poll GET /bootstrap.",
		})
		return
	}
	_, etag, _, _, err := environment.Snapshot(req.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": err.Error()})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"message": "streaming unsupported"})
		return
	}
	changes, unsubscribe := environment.Subscribe()
	defer unsubscribe()

	w.Header().Set("content-type", "text/event-stream")
	w.Header().Set("cache-control", "no-cache")
	w.Header().Set("connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	writeEvent(w, "ruleset", map[string]any{"environmentId": environment.StreamID(), "etag": etag})
	flusher.Flush()

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-req.Context().Done():
			return
		case <-changes:
			writeEvent(w, "ruleset", map[string]any{"environmentId": environment.StreamID(), "changedAt": time.Now().UnixMilli()})
			flusher.Flush()
		case <-ticker.C:
			writeEvent(w, "heartbeat", map[string]any{})
			flusher.Flush()
		}
	}
}

func writeEvent(w http.ResponseWriter, event string, data any) {
	encoded, _ := json.Marshal(data)
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, encoded)
}

// receiveExposures buffers exposures for the environment the key belongs to.
// They are forwarded with that environment's server key.
func (r *Relay) receiveExposures(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	environment, _ := r.authenticate(bearer(req))
	if environment == nil {
		unauthorized(w)
		return
	}
	var body struct {
		Exposures []json.RawMessage `json:"exposures"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4<<20)).Decode(&body); err != nil || body.Exposures == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"statusCode": 400, "message": "invalid exposures"})
		return
	}
	if len(body.Exposures) > exposureBatch {
		writeJSON(w, http.StatusBadRequest, map[string]any{"statusCode": 400, "message": "exposures must contain no more than 1000 elements"})
		return
	}
	environment.exposures.Add(body.Exposures)
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": len(body.Exposures)})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
