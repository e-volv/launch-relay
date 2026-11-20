package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const fixtureRuleset = `{"rulesetVersion":2,"environmentId":"flag_environment:prod","etag":"%s","flags":{
 "public.banner":{"definition":{"key":"public.banner","type":"boolean","variants":[{"key":"on","value":true},{"key":"off","value":false}],"clientSideAvailable":true},"targeting":{"on":true,"defaultVariant":"on","rules":[]}},
 "mobile.only":{"definition":{"key":"mobile.only","type":"boolean","variants":[{"key":"on","value":true}],"mobileAvailable":true},"targeting":{"on":true,"defaultVariant":"on","rules":[]}},
 "server.secret":{"definition":{"key":"server.secret","type":"boolean","variants":[{"key":"on","value":true}]},"targeting":{"on":true,"defaultVariant":"on","rules":[]}},
 "empty.variants":{"definition":{"key":"empty.variants","type":"boolean","variants":[],"clientSideAvailable":true},"targeting":{"on":true,"defaultVariant":"on","rules":[]}}
},"segments":{}}`

// upstream is a fake e-volv control plane recording what reaches it.
type upstream struct {
	mu        sync.Mutex
	etag      string
	healthy   bool
	exposures map[string]int // by authorization header
	status    int
}

func newUpstream() *upstream {
	return &upstream{etag: "one", healthy: true, exposures: map[string]int{}}
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.healthy {
		w.WriteHeader(500)
		return
	}
	switch r.URL.Path {
	case "/api/public/v1/flags/bootstrap":
		if strings.ReplaceAll(r.Header.Get("if-none-match"), `"`, "") == u.etag {
			w.WriteHeader(304)
			return
		}
		_, _ = fmt.Fprintf(w, fixtureRuleset, u.etag)
	case "/api/public/v1/flags/exposures":
		if u.status != 0 {
			w.WriteHeader(u.status)
			return
		}
		var body struct {
			Exposures []json.RawMessage `json:"exposures"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		u.exposures[r.Header.Get("authorization")] += len(body.Exposures)
		w.WriteHeader(202)
	}
}

func newTestRelay(t *testing.T, server *httptest.Server) *Relay {
	t.Helper()
	environments, err := parseEnvironments(
		"prod=evk_prod,staging=evk_staging",
		"prod=evk_pub_prod_a|evk_pub_prod_b,staging=evk_pub_staging",
		server.URL, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, environment := range environments {
		environment.HTTP = server.Client()
	}
	return &Relay{environments: environments, cancel: func() {}}
}

func get(t *testing.T, handler http.Handler, path, key string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if key != "" {
		req.Header.Set("authorization", "Bearer "+key)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestClientKeyOnlyGetsClientSideFlags(t *testing.T) {
	server := httptest.NewServer(newUpstream())
	defer server.Close()
	relay := newTestRelay(t, server)
	routes := relay.Routes()

	rec := get(t, routes, "/bootstrap", "evk_pub_prod_a")
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var body struct {
		EnvironmentID string                    `json:"environmentId"`
		Flags         map[string]map[string]any `json:"flags"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body.Flags["server.secret"]; ok {
		t.Fatal("client key received a server-only flag")
	}
	if _, ok := body.Flags["mobile.only"]; ok {
		t.Fatal("web client received a mobile-only flag")
	}
	if body.Flags["public.banner"]["value"] != true {
		t.Fatalf("public.banner=%v", body.Flags["public.banner"])
	}
	if got, ok := body.Flags["empty.variants"]; !ok || got["value"] != nil {
		t.Fatalf("empty.variants=%v", got)
	}
	if body.EnvironmentID != "flag_environment:prod" {
		t.Fatalf("environmentId=%q", body.EnvironmentID)
	}
	if strings.Contains(rec.Body.String(), "targeting") {
		t.Fatal("client response carries rules")
	}

	rec = get(t, routes, "/bootstrap", "evk_pub_prod_b", "x-evolve-app-id", "com.example")
	body.Flags = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if _, ok := body.Flags["mobile.only"]; !ok || len(body.Flags) != 1 {
		t.Fatalf("mobile flags=%v", body.Flags)
	}

	// A server key still gets the full ruleset, conditionally.
	rec = get(t, routes, "/bootstrap", "evk_prod")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "server.secret") || rec.Header().Get("etag") != `"one"` {
		t.Fatalf("server bootstrap status=%d etag=%q", rec.Code, rec.Header().Get("etag"))
	}
	if rec = get(t, routes, "/bootstrap", "evk_prod", "if-none-match", `"one"`); rec.Code != 304 {
		t.Fatalf("conditional status=%d", rec.Code)
	}
}

func TestAuthRequiresAnExactConfiguredKey(t *testing.T) {
	server := httptest.NewServer(newUpstream())
	defer server.Close()
	relay := newTestRelay(t, server)
	routes := relay.Routes()

	for _, key := range []string{"", "evk_pub_anything", "evk_pub_prod_a_extra", "evk_pub_prod_", "evk_pro", "evk_prod2", "Bearer evk_prod"} {
		if rec := get(t, routes, "/bootstrap", key); rec.Code != 401 {
			t.Errorf("key %q status=%d", key, rec.Code)
		}
	}
	// Several environments: each client key reaches its own.
	for key, want := range map[string]string{"evk_pub_prod_a": "prod", "evk_pub_staging": "staging", "evk_staging": "staging"} {
		environment, _ := relay.authenticate(key)
		if environment == nil || environment.ID != want {
			t.Errorf("key %q -> %v, want %s", key, environment, want)
		}
	}
	if rec := get(t, routes, "/stream", "evk_pub_prod_a"); rec.Code != 403 {
		t.Errorf("client stream status=%d", rec.Code)
	}

	post := func(key string) int {
		req := httptest.NewRequest("POST", "/exposures", strings.NewReader(`{"exposures":[{"flagKey":"a"}]}`))
		if key != "" {
			req.Header.Set("authorization", "Bearer "+key)
		}
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := post(""); code != 401 {
		t.Errorf("unauthenticated exposures status=%d", code)
	}
	if code := post("evk_pub_nope"); code != 401 {
		t.Errorf("unknown key exposures status=%d", code)
	}
	if code := post("evk_pub_staging"); code != 202 {
		t.Errorf("staging exposures status=%d", code)
	}
	if relay.environments[1].exposures.Len() != 1 || relay.environments[0].exposures.Len() != 0 {
		t.Fatal("exposure routed to the wrong environment")
	}
}

func TestParseEnvironmentsRejectsBadConfig(t *testing.T) {
	cases := [][2]string{
		{"", ""},
		{"evk_prod", ""},
		{"prod=evk_pub_x", ""},
		{"prod=evk_a,prod=evk_b", ""},
		{"prod=evk_a", "staging=evk_pub_x"},
		{"prod=evk_a", "prod=evk_b"},
	}
	for _, c := range cases {
		if _, err := parseEnvironments(c[0], c[1], "http://x", t.TempDir()); err == nil {
			t.Errorf("keys=%q client=%q accepted", c[0], c[1])
		}
	}
}

func TestExposuresForwardPerEnvironment(t *testing.T) {
	up := newUpstream()
	server := httptest.NewServer(up)
	defer server.Close()
	relay := newTestRelay(t, server)
	prod, staging := relay.environments[0], relay.environments[1]
	rows := make([]json.RawMessage, 1500)
	for i := range rows {
		rows[i] = row(i)
	}
	prod.exposures.Add(rows)
	staging.exposures.Add([]json.RawMessage{json.RawMessage(`{}`), json.RawMessage(`{}`)})
	for _, environment := range relay.environments {
		environment.flushExposures(context.Background())
	}
	if up.exposures["Bearer evk_prod"] != 1500 || up.exposures["Bearer evk_staging"] != 2 {
		t.Fatalf("forwarded=%v", up.exposures)
	}
	if prod.exposures.Len() != 0 || staging.exposures.Len() != 0 {
		t.Fatal("buffers not drained")
	}

	// A failed send is requeued, not lost.
	up.status = 503
	staging.exposures.Add([]json.RawMessage{json.RawMessage(`{}`)})
	staging.flushExposures(context.Background())
	if staging.exposures.Len() != 1 {
		t.Fatalf("len=%d after failed send", staging.exposures.Len())
	}
}

func row(i int) json.RawMessage { return json.RawMessage(fmt.Sprintf(`{"i":%d}`, i)) }

func TestExposureBufferDropsOldest(t *testing.T) {
	var buffer ExposureBuffer
	for i := 0; i < exposureCap+1; i++ {
		buffer.Add([]json.RawMessage{row(i)})
	}
	if buffer.Len() != exposureCap || string(buffer.items[0]) != `{"i":1}` {
		t.Fatalf("len=%d first=%s", buffer.Len(), buffer.items[0])
	}
}

func TestExposureRequeueDropsOldest(t *testing.T) {
	var buffer ExposureBuffer
	for i := 0; i < exposureCap; i++ {
		buffer.Add([]json.RawMessage{row(i)})
	}
	batch := buffer.Drain(3) // rows 0..2, the oldest
	buffer.Add([]json.RawMessage{row(exposureCap), row(exposureCap + 1)})
	buffer.Requeue(batch)
	if buffer.Len() != exposureCap {
		t.Fatalf("len=%d", buffer.Len())
	}
	if string(buffer.items[0]) != `{"i":2}` {
		t.Fatalf("first=%s, want the oldest dropped", buffer.items[0])
	}
	if last := buffer.items[len(buffer.items)-1]; string(last) != fmt.Sprintf(`{"i":%d}`, exposureCap+1) {
		t.Fatalf("last=%s, newest row lost", last)
	}
}

func TestSnapshotSurvivesUpstreamLossAndRecovers(t *testing.T) {
	up := newUpstream()
	server := httptest.NewServer(up)
	defer server.Close()
	environment := &Environment{ID: "env", ServerKey: "key", Upstream: server.URL, SnapshotPath: filepath.Join(t.TempDir(), "snapshot.json"), HTTP: server.Client()}
	if err := environment.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	up.mu.Lock()
	up.healthy = false
	up.mu.Unlock()
	if err := environment.Refresh(context.Background()); err == nil {
		t.Fatal("expected upstream error")
	}
	snapshot, _, stale, _, err := environment.Snapshot(context.Background())
	if err != nil || !stale || !json.Valid(snapshot) {
		t.Fatalf("snapshot=%s stale=%v err=%v", snapshot, stale, err)
	}

	// A fresh process with only the disk snapshot serves it, stale.
	restarted := &Environment{ID: "env", ServerKey: "key", Upstream: server.URL, SnapshotPath: environment.SnapshotPath, HTTP: server.Client()}
	if err := restarted.Load(); err != nil {
		t.Fatal(err)
	}
	if _, etag, stale, _, err := restarted.Snapshot(context.Background()); err != nil || !stale || etag != "one" {
		t.Fatalf("restarted etag=%q stale=%v err=%v", etag, stale, err)
	}

	up.mu.Lock()
	up.healthy = true
	up.mu.Unlock()
	if err := environment.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, stale, _, _ = environment.Snapshot(context.Background()); stale {
		t.Fatal("expected recovery")
	}
}

func TestRefreshKeepsRulesetWhenDiskWriteFails(t *testing.T) {
	server := httptest.NewServer(newUpstream())
	defer server.Close()
	dir := t.TempDir()
	environment := &Environment{ID: "env", ServerKey: "key", Upstream: server.URL, SnapshotPath: filepath.Join(dir, "missing", "\x00bad"), HTTP: server.Client()}
	if err := environment.Refresh(context.Background()); err == nil {
		t.Fatal("expected a disk error")
	}
	if _, etag, stale, _, err := environment.Snapshot(context.Background()); err != nil || etag != "one" || stale {
		t.Fatalf("etag=%q stale=%v err=%v", etag, stale, err)
	}
}

func TestRefreshIgnoresRequesterCancellation(t *testing.T) {
	server := httptest.NewServer(newUpstream())
	defer server.Close()
	environment := &Environment{ID: "env", ServerKey: "key", Upstream: server.URL, SnapshotPath: filepath.Join(t.TempDir(), "s.json"), HTTP: server.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, _, err := environment.Snapshot(ctx); err != nil {
		t.Fatalf("a cancelled requester aborted the refresh: %v", err)
	}
}

func TestStreamPushesWhenEtagChanges(t *testing.T) {
	up := newUpstream()
	server := httptest.NewServer(up)
	defer server.Close()
	relay := newTestRelay(t, server)
	front := httptest.NewServer(relay.Routes())
	defer front.Close()

	req, _ := http.NewRequest("GET", front.URL+"/stream", nil)
	req.Header.Set("authorization", "Bearer evk_prod")
	res, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("status=%d %s", res.StatusCode, body)
	}
	events := make(chan string, 8)
	go func() {
		scanner := bufio.NewScanner(res.Body)
		for scanner.Scan() {
			if line := scanner.Text(); strings.HasPrefix(line, "data: ") {
				events <- line
			}
		}
		close(events)
	}()
	next := func() string {
		select {
		case line := <-events:
			return line
		case <-time.After(5 * time.Second):
			t.Fatal("no event")
			return ""
		}
	}
	if hello := next(); !strings.Contains(hello, `"etag":"one"`) || !strings.Contains(hello, `"environmentId":"flag_environment:prod"`) {
		t.Fatalf("hello=%s", hello)
	}

	// Unchanged etag: no event.
	_ = relay.environments[0].Refresh(context.Background())
	up.mu.Lock()
	up.etag = "two"
	up.mu.Unlock()
	_ = relay.environments[0].Refresh(context.Background())
	if change := next(); !strings.Contains(change, `"changedAt"`) {
		t.Fatalf("change=%s", change)
	}
	select {
	case extra := <-events:
		t.Fatalf("unexpected event %s", extra)
	case <-time.After(100 * time.Millisecond):
	}
}
