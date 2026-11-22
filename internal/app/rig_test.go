package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"idp-mcp-bridge/internal/auth"
	"idp-mcp-bridge/internal/bridge"
	"idp-mcp-bridge/internal/config"
	"idp-mcp-bridge/internal/egress"
	"idp-mcp-bridge/internal/mcp/mcptest"
	"idp-mcp-bridge/internal/thirdparty"
)

const base = "http://bridge.test:8680"

// clock is a clock the tests move.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// tokens is a TokenSource double: the tokens by member, the subjects it was asked about, and what Refresh gives.
type tokens struct {
	mu      sync.Mutex
	by      map[auth.Subject]string
	asked   []auth.Subject
	refresh func(rejected string) (string, error)
}

func (t *tokens) Token(_ context.Context, who auth.Subject, connection string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.asked = append(t.asked, who)
	if tok, ok := t.by[who]; ok {
		return tok, nil
	}
	return "", auth.ErrNoToken
}

func (t *tokens) Refresh(_ context.Context, who auth.Subject, connection, rejected string) (string, error) {
	if t.refresh == nil {
		return "", auth.ErrNoToken
	}
	return t.refresh(rejected)
}

func (t *tokens) Asked() []auth.Subject {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]auth.Subject(nil), t.asked...)
}

// rig is a bridge in front of a third-party double, with a gateway that signs for it.
type rig struct {
	t      *testing.T
	gw     *mcptest.Gateway
	tp     *thirdparty.Double
	h      http.Handler
	log    *bytes.Buffer
	met    *bridge.Metrics
	tok    *tokens
	clock  *clock
	opts   Options
	config []config.Connection
}

type rigOpt func(*rig, *string)

// yaml for the connections: svc needs no token, needs-auth is an oauth connection
func connectionsYAML(endpoint, extra string) string {
	return fmt.Sprintf(`
connections:
  - id: svc
    title: Test Service
    endpoint: %[1]s
    authorization: {mode: none}
%[2]s
  - id: needs-auth
    title: Notes
    endpoint: %[1]s
    authorization:
      mode: oauth
      issuer: %[3]s
      client: {mode: cimd, document: %[3]s/client.json}
      scopes: [read]
`, endpoint, extra, endpoint[:len(endpoint)-len("/mcp")])
}

func newRig(t *testing.T, extra string, mod func(*rig)) *rig {
	t.Helper()
	r := &rig{t: t, gw: mcptest.New(), tp: thirdparty.New(), log: &bytes.Buffer{}, met: bridge.NewMetrics(),
		tok: &tokens{by: map[auth.Subject]string{}}, clock: &clock{t: time.Now()}}
	t.Cleanup(r.tp.Close)
	r.opts = Options{BaseURL: base, Version: "test", CallTimeout: 10 * time.Second,
		Egress: egress.Options{TestOrigins: map[string]bool{r.tp.Origin(): true}}}
	if mod != nil {
		mod(r)
	}
	cs, err := config.Parse([]byte(connectionsYAML(r.tp.URL(), extra)), config.Options{TestOrigins: r.opts.Egress.TestOrigins})
	if err != nil {
		t.Fatal(err)
	}
	r.config = cs
	r.opts.CallerKeysPEM = r.gw.PEM()
	r.opts.Deps = bridge.Deps{Tokens: r.tok, Reviewer: auth.NoReviewer{}, Log: slog.New(slog.NewJSONHandler(r.log, nil)), Metrics: r.met, Now: r.clock.Now}
	if r.h, err = Handler(cs, r.opts); err != nil {
		t.Fatal(err)
	}
	return r
}

// call sends a signed tools/call to a connection as the gateway would and returns the answer.
func (r *rig) call(conn, subject, tenant, tool, args string) (*httptest.ResponseRecorder, map[string]any) {
	r.t.Helper()
	return mcptest.Post(r.h, Path(conn), r.gw.CallBody(Audience(base, conn), subject, tenant, tool, args, ""), nil)
}

// result is the "result" of an answer, failing the test if there is none.
func result(t *testing.T, w *httptest.ResponseRecorder, m map[string]any) map[string]any {
	t.Helper()
	res, _ := m["result"].(map[string]any)
	if w.Code != 200 || res == nil {
		t.Fatalf("no result: %d %s", w.Code, w.Body)
	}
	return res
}

func text(res map[string]any) string {
	c, _ := res["content"].([]any)
	if len(c) == 0 {
		return ""
	}
	s, _ := c[0].(map[string]any)["text"].(string)
	return s
}

func asJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
