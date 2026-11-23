package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"idp-mcp-bridge/internal/api"
	"idp-mcp-bridge/internal/asdouble"
	"idp-mcp-bridge/internal/auth"
	"idp-mcp-bridge/internal/bridge"
	"idp-mcp-bridge/internal/config"
	"idp-mcp-bridge/internal/egress"
	"idp-mcp-bridge/internal/githubdouble"
	"idp-mcp-bridge/internal/grants"
	"idp-mcp-bridge/internal/grants/pgtest"
	"idp-mcp-bridge/internal/mcp/mcptest"
	"idp-mcp-bridge/internal/oauth"
	"idp-mcp-bridge/internal/sealer"
	"idp-mcp-bridge/internal/thirdparty"
)

const redirectURI = "https://workspace.example.com/oauth/callback"

// storeKind is a way to make the store the flows run over: memory always, PostgreSQL when the tests have a database.
type storeKind struct {
	name string
	// make returns a store, and a function that opens another store over the same data (another replica).
	make func(t *testing.T) (grants.Store, func() grants.Store)
}

func storeKinds() []storeKind {
	kinds := []storeKind{{"memory", func(t *testing.T) (grants.Store, func() grants.Store) {
		m := grants.NewMemory()
		return m, func() grants.Store { return m }
	}}}
	if pgtest.Enabled() {
		kinds = append(kinds, storeKind{"postgres", func(t *testing.T) (grants.Store, func() grants.Store) {
			_, url := pgtest.Scratch(t) // migrated by the owner; the server runs as the app role, which cannot change the schema
			open := func() grants.Store {
				s, err := grants.Open(context.Background(), url)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(s.Close)
				return s
			}
			return open(), open
		}})
	}
	return kinds
}

func forStores(t *testing.T, f func(t *testing.T, k storeKind)) {
	for _, k := range storeKinds() {
		t.Run(k.name, func(t *testing.T) { f(t, k) })
	}
}

func testKeys(t *testing.T, ids ...string) *sealer.Keys {
	t.Helper()
	var lines []string
	for _, id := range ids {
		raw := bytes.Repeat([]byte{id[len(id)-1]}, 32) // the same id is always the same key
		lines = append(lines, id+":"+base64.StdEncoding.EncodeToString(raw))
	}
	k, err := sealer.Parse([]byte(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// orig is the bridge with OAuth in front of a third-party double and an authorization-server double.
type orig struct {
	t     *testing.T
	gw    *mcptest.Gateway
	tp    *thirdparty.Double
	as    *asdouble.Server
	gh    *githubdouble.Server
	doc   *httptest.Server
	store grants.Store
	keys  *sealer.Keys
	svc   *oauth.Service
	mcp   http.Handler
	api   http.Handler
	log   *bytes.Buffer
	met   *bridge.Metrics
	conns []config.Connection
	open  func() grants.Store

	mu   sync.Mutex
	seen []string // every answer the bridge gave, for the search for secrets
}

type orgOpts struct {
	yaml  func(r *orig) string // the connections
	mod   func(r *orig)        // before anything is built
	store storeKind
	dcr   bool
}

func defaultYAML(r *orig) string {
	return fmt.Sprintf(`
connections:
  - id: notes
    title: Notes
    endpoint: %[1]s
    authorization:
      mode: oauth
      issuer: %[2]s
      client: {mode: cimd, document: "%[3]s/clients/notes.json"}
      scopes: [read]
      reviewerScopes: [list]
  - id: svc
    title: Open service
    endpoint: %[1]s
    authorization: {mode: none}
`, r.tp.URL(), r.as.Issuer(), r.doc.URL)
}

func newORig(t *testing.T, o orgOpts) *orig {
	t.Helper()
	if o.store.make == nil {
		o.store = storeKinds()[0]
	}
	r := &orig{t: t, gw: mcptest.New(), tp: thirdparty.New(), as: asdouble.New(), gh: githubdouble.New("Iv1.abc", "s3cret"), log: &bytes.Buffer{}, met: bridge.NewMetrics(), keys: testKeys(t, "k1")}
	t.Cleanup(r.tp.Close)
	t.Cleanup(r.as.Close)
	t.Cleanup(r.gh.Close)
	r.as.CIMD = true
	r.store, r.open = o.store.make(t)
	// the Workspace serves the client metadata document; its content is the bridge's (svc.ClientMetadata)
	r.doc = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		id := strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, "/clients/"), ".json")
		m, err := r.svc.ClientMetadata(id)
		if err != nil {
			http.NotFound(w, req)
			return
		}
		_ = json.NewEncoder(w).Encode(m)
	}))
	t.Cleanup(r.doc.Close)
	r.tp.Check = r.as.Check
	r.tp.ChallengeMetadata = true
	r.tp.PRM = map[string]any{"resource": r.tp.URL(), "authorization_servers": []string{r.as.Issuer()}, "scopes_supported": []string{"read", "write"}}
	if o.mod != nil {
		o.mod(r)
	}
	origins := map[string]bool{r.tp.Origin(): true, r.as.Origin(): true, r.gh.Origin(): true, strings.TrimPrefix(r.doc.URL, "http://"): true}
	yaml := defaultYAML
	if o.yaml != nil {
		yaml = o.yaml
	}
	cs, err := config.Parse([]byte(yaml(r)), config.Options{TestOrigins: origins})
	if err != nil {
		t.Fatal(err)
	}
	r.conns = cs
	hc := egress.NewClient(egress.Options{TestOrigins: origins})
	opts := Options{BaseURL: base, CallerKeysPEM: r.gw.PEM(), Version: "test", CallTimeout: 10 * time.Second, HTTP: hc}
	f := &oauth.Fetcher{HTTP: hc, TestOrigins: origins}
	log := slog.New(slog.NewJSONHandler(r.log, nil))
	r.svc = &oauth.Service{Connections: cs, RedirectURI: redirectURI, Store: r.store, Sealer: r.keys, F: f, Log: log,
		Disc: &oauth.Discoverer{F: f, Probe: Prober(cs, hc, opts)}}
	opts.Deps = bridge.Deps{Tokens: r.svc, Reviewer: oauth.ReviewerSource{S: r.svc}, Log: log, Metrics: r.met}
	if r.mcp, err = Handler(cs, opts); err != nil {
		t.Fatal(err)
	}
	r.svc.Counters = r.met
	r.svc.GitHubAPI = r.gh.URL
	h := api.New(testAuthenticator{}, r.svc)
	h.EnableOffboarding(testServiceAuth{}, oauth.OffboardAPI{S: r.svc})
	r.api = h
	return r
}

// testServiceAuth is the verifier of the "member left" route as the tests need it: "svc:<azp>" is a service token of that client (the
// allow-list is lifecycle and lifecycle2), "m:..." and "r:..." are members' tokens, anything else is not a token.
type testServiceAuth struct{}

func (testServiceAuth) AuthenticateService(_ context.Context, bearer string) (string, error) {
	if azp, ok := strings.CutPrefix(bearer, "svc:"); ok {
		if azp == "lifecycle" || azp == "lifecycle2" {
			return azp, nil
		}
		return "", api.ErrForbidden
	}
	if strings.HasPrefix(bearer, "m:") || strings.HasPrefix(bearer, "r:") {
		return "", api.ErrForbidden
	}
	return "", api.ErrUnauthenticated
}

// testAuthenticator takes "Bearer m:<tenant>:<member>" for the token the Workspace would send, and "r:<tenant>:<member>" for the
// token of a member who has the reviewer role.
type testAuthenticator struct{}

func (testAuthenticator) Authenticate(_ context.Context, bearer string) (auth.Subject, error) {
	p := strings.Split(bearer, ":")
	if len(p) != 3 || (p[0] != "m" && p[0] != "r") {
		return auth.Subject{}, api.ErrUnauthenticated
	}
	return auth.Subject{Tenant: p[1], Member: p[2], Reviewer: p[0] == "r"}, nil
}

func (r *orig) record(body string) {
	r.mu.Lock()
	r.seen = append(r.seen, body)
	r.mu.Unlock()
}

// callAPI calls the internal API as a member (tenant "acme").
func (r *orig) callAPI(method, path, member, body string) (int, map[string]any) {
	return r.callAPIAs(method, path, "acme", member, body)
}

func (r *orig) callAPIAs(method, path, tenant, member, body string) (int, map[string]any) {
	return r.callAPIKind(method, path, "m", tenant, member, body)
}

// callAPIReviewer calls the API as an operator whose token carries the reviewer role.
func (r *orig) callAPIReviewer(method, path, member, body string) (int, map[string]any) {
	return r.callAPIKind(method, path, "r", "acme", member, body)
}

func (r *orig) callAPIKind(method, path, kind, tenant, member, body string) (int, map[string]any) {
	req := httptest.NewRequest(method, "/internal/v1/connections"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+kind+":"+tenant+":"+member)
	w := httptest.NewRecorder()
	r.api.ServeHTTP(w, req)
	if !(strings.HasSuffix(path, "/authorization") && w.Code == 200) { // the authorization URL carries the state and the challenge by design
		r.record(w.Body.String())
	}
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m
}

// connect runs the whole authorization as a member: start, the member's consent at the authorization server, the callback.
func (r *orig) connect(member string) (int, map[string]any) {
	r.t.Helper()
	return r.connectAs("acme", member, "notes")
}

func (r *orig) connectAs(tenant, member, conn string) (int, map[string]any) {
	r.t.Helper()
	code, m := r.callAPIAs("POST", "/"+conn+"/authorization", tenant, member, "")
	if code != 200 {
		return code, m
	}
	back, err := asdouble.Consent(m["url"].(string), member)
	if err != nil {
		r.t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"code": back.Get("code"), "state": back.Get("state"), "iss": back.Get("iss"), "error": back.Get("error")})
	return r.callAPIAs("POST", "/"+conn+"/callback", tenant, member, string(body))
}

// call makes a signed tools/call to a connection as the gateway would.
func (r *orig) call(conn, tenant, member, tool string) (*httptest.ResponseRecorder, map[string]any) {
	r.t.Helper()
	w, m := mcptest.Post(r.mcp, Path(conn), r.gw.CallBody(Audience(base, conn), member, tenant, tool, `{}`, ""), nil)
	r.record(w.Body.String())
	return w, m
}

// authorizeReviewer runs the whole authorization of a connection's reviewer account as an operator.
func (r *orig) authorizeReviewer(operator string) (int, map[string]any) {
	r.t.Helper()
	code, m := r.callAPIReviewer("POST", "/notes/reviewer/authorization", operator, "")
	if code != 200 {
		return code, m
	}
	back, err := asdouble.Consent(m["url"].(string), "reviewer-account") // the account at the third party is its own user
	if err != nil {
		r.t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"code": back.Get("code"), "state": back.Get("state"), "iss": back.Get("iss")})
	return r.callAPIReviewer("POST", "/notes/callback", operator, string(body))
}

// list is the gateway's tools/list of a connection (no member).
func (r *orig) list(conn string) (*httptest.ResponseRecorder, map[string]any) {
	w, m := mcptest.Post(r.mcp, Path(conn), mcptest.ListBody(), nil)
	r.record(w.Body.String())
	return w, m
}

func (r *orig) authRequired(res map[string]any) bool {
	sc, _ := json.Marshal(res["structuredContent"])
	return res["isError"] == true && string(sc) == `{"io.idp.telos/authorizationRequired":{"connection":"notes"}}`
}

// noSecretsAnywhere searches what the bridge answered, logged and counted for every secret of the authorization server and for
// the extra ones given.
func (r *orig) noSecretsAnywhere(extra ...string) {
	r.t.Helper()
	all := r.log.String() + r.metricsText()
	r.mu.Lock()
	all += strings.Join(r.seen, "\n")
	r.mu.Unlock()
	secrets := append(r.as.Secrets(), extra...)
	if len(secrets) == 0 {
		r.t.Fatal("no secrets to look for: the test is not testing anything")
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(all, s) {
			r.t.Errorf("a secret (%.6s...) is in what the bridge answered, logged or counted", s)
		}
	}
}

func (r *orig) metricsText() string {
	w := httptest.NewRecorder()
	r.met.Write(w)
	return w.Body.String()
}

func (r *orig) tokenOf(member string) string {
	r.t.Helper()
	tok, err := r.svc.Token(context.Background(), auth.Subject{Tenant: "acme", Member: member}, "notes")
	if err != nil {
		r.t.Fatal(err)
	}
	return tok
}

func query(raw string) url.Values {
	u, _ := url.Parse(raw)
	return u.Query()
}
