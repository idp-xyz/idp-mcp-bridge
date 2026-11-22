package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"idp-mcp-bridge/internal/asdouble"
	"idp-mcp-bridge/internal/auth"
	"idp-mcp-bridge/internal/grants"
	"idp-mcp-bridge/internal/sealer"
)

var bobKey = grants.Key{Tenant: "acme", Member: "bob", Connection: "notes"}

// PATH O of the plan's section 4, items 1, 2, 3 and 7: bob connects, his run reaches the third party with his token and no
// identity, alice has not connected and the third party hears nothing, and no secret is anywhere it should not be.
func TestBobConnectsHisRunCallsWithHisTokenAndAliceIsToldToConnect(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		code, m := r.connect("bob")
		if code != 200 || m["status"] != "connected" {
			t.Fatalf("%d %v", code, m)
		}
		// 1. the grant is in the store, and encrypted
		g, err := r.store.Get(context.Background(), bobKey)
		if err != nil {
			t.Fatal(err)
		}
		tok := r.tokenOf("bob")
		rt := r.as.RefreshTokenOf("bob")
		if rt == "" || bytes.Contains(g.SealedAccess, []byte(tok)) || bytes.Contains(g.SealedRefresh, []byte(rt)) {
			t.Fatal("a token is in the store in clear, or there is no refresh token")
		}
		if id, _ := sealer.KeyID(g.SealedAccess); id != "k1" || g.Scope != "read" || g.Issuer != r.as.Issuer() {
			t.Fatalf("%q %+v", id, g)
		}
		// 2. bob's run: the third party gets bob's token and no identity
		w, m := r.call("notes", "acme", "bob", "whoami")
		if res := result(t, w, m); text(res) != "token of bob" || res["isError"] != nil {
			t.Fatalf("%s", w.Body)
		}
		calls := r.tp.Calls()
		if len(calls) != 1 || calls[0].Header.Get("Authorization") != "Bearer "+tok {
			t.Fatalf("%+v", calls)
		}
		all := string(calls[0].Body) + asJSON(calls[0].Header)
		for _, s := range []string{"bob", "acme", "eyJ", "idp-host"} {
			if strings.Contains(strings.ToLower(all), s) && s != "eyJ" || strings.Contains(all, "eyJ") {
				t.Errorf("the third party received %q: %s", s, all)
			}
		}
		// 3. alice has not connected: authorization required, and not one request reaches the third party
		before := len(r.tp.Requests())
		w, m = r.call("notes", "acme", "alice", "whoami")
		if res := result(t, w, m); !r.authRequired(res) || strings.Contains(w.Body.String(), "://") {
			t.Fatalf("%s", w.Body)
		}
		if len(r.tp.Requests()) != before {
			t.Fatal("the third party received a request for a member who has not authorized")
		}
		// 7. no token, code, verifier, state or client secret in anything the bridge said
		r.noSecretsAnywhere(tok, rt)
	})
}

func TestTheAuthorizationAddressCarriesPKCEStateResourceAndScopeAndNothingOfTheMember(t *testing.T) {
	r := newORig(t, orgOpts{})
	code, m := r.callAPI("POST", "/notes/authorization", "bob", `{"member":"alice","tenant":"other","redirect_uri":"https://evil.example.com/"}`)
	if code != 200 {
		t.Fatalf("%d %v", code, m)
	}
	q := query(m["url"].(string))
	if !strings.HasPrefix(m["url"].(string), r.as.Issuer()+"/authorize?") || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		len(q.Get("code_challenge")) != 43 || len(q.Get("state")) != 43 || q.Get("resource") != r.tp.URL() || q.Get("scope") != "read" ||
		q.Get("client_id") != r.doc.URL+"/clients/notes.json" || q.Get("redirect_uri") != redirectURI {
		t.Fatalf("%v", q)
	}
	for _, v := range q {
		if strings.Contains(strings.Join(v, ""), "bob") || strings.Contains(strings.Join(v, ""), "evil") || strings.Contains(strings.Join(v, ""), "acme") {
			t.Fatalf("the address carries something of the member or the request: %v", q)
		}
	}
	// the state belongs to the authenticated member, not to who the body names
	back, _ := asdoubleConsent(t, m["url"].(string), "bob")
	body, _ := json.Marshal(map[string]string{"code": back.Get("code"), "state": back.Get("state")})
	if code, _ = r.callAPI("POST", "/notes/callback", "alice", string(body)); code != 400 {
		t.Fatalf("alice finished bob's authorization: %d", code)
	}
	if code, _ = r.callAPI("POST", "/notes/callback", "bob", string(body)); code != 200 {
		t.Fatalf("bob could not finish his own after alice tried: %d", code)
	}
	// two starts give two states and two challenges
	_, m2 := r.callAPI("POST", "/notes/authorization", "bob", "")
	_, m3 := r.callAPI("POST", "/notes/authorization", "bob", "")
	if query(m2["url"].(string)).Get("state") == query(m3["url"].(string)).Get("state") || query(m2["url"].(string)).Get("code_challenge") == query(m3["url"].(string)).Get("code_challenge") {
		t.Fatal("two starts share a state or a challenge")
	}
}

func TestTheTokenIsRenewedBeforeItExpiresAndAfterTheThirdPartyRefusesIt(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		r.as.ExpiresIn = 30 // inside the 60 seconds the bridge renews ahead of
		if code, m := r.connect("bob"); code != 200 {
			t.Fatalf("%d %v", code, m)
		}
		first := r.tokenOf("bob") // asking renews it: it is within the window
		if r.as.Count("/token", "refresh_token") != 1 {
			t.Fatalf("%d refreshes", r.as.Count("/token", "refresh_token"))
		}
		w, m := r.call("notes", "acme", "bob", "whoami")
		if text(result(t, w, m)) != "token of bob" {
			t.Fatalf("%s", w.Body)
		}
		if used := r.tp.Calls()[0].Header.Get("Authorization"); used == "Bearer "+first {
			t.Fatal("the call used a token that was about to expire instead of a renewed one")
		}
		// the refresh asked for the resource (RFC 8707) and sent the refresh token
		last := r.as.Requests("/token")[len(r.as.Requests("/token"))-1]
		if last.Form.Get("resource") != r.tp.URL() || last.Form.Get("grant_type") != "refresh_token" || last.Form.Get("refresh_token") == "" {
			t.Fatalf("%v", last.Form)
		}

		// the third party refuses a token the bridge thinks is good: 401, one renewal, one retry, the call succeeds
		r.as.ExpiresIn = 3600
		r.tokenOf("bob") // a long-lived one now
		n := r.as.Count("/token", "refresh_token")
		r.as.ExpireAll()
		w, m = r.call("notes", "acme", "bob", "whoami")
		if res := result(t, w, m); text(res) != "token of bob" || res["isError"] != nil {
			t.Fatalf("%s", w.Body)
		}
		if got := r.as.Count("/token", "refresh_token"); got != n+1 {
			t.Fatalf("%d refreshes, want %d", got, n+1)
		}
		r.noSecretsAnywhere()
	})
}

func TestRefreshTokenRotationIsHonouredAndAnOmittedScopeAndRefreshTokenAreKept(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.as.Rotate = true
	r.as.ExpiresIn = 30
	r.connect("bob")
	rt1 := r.as.RefreshTokenOf("bob")
	r.tokenOf("bob")
	rt2 := r.as.RefreshTokenOf("bob")
	if rt1 == rt2 || r.as.Revoked(rt1) == false {
		t.Fatal("the server did not rotate")
	}
	r.tokenOf("bob") // spends rt2, which is the stored one: a client that kept rt1 would be refused
	if r.as.Count("/token", "refresh_token") != 2 {
		t.Fatalf("%d", r.as.Count("/token", "refresh_token"))
	}
	if _, err := r.store.Get(context.Background(), bobKey); err != nil {
		t.Fatal("the grant was dropped after a rotation")
	}
	// no rotation, no scope in the answer: both stay as they were (RFC 6749 section 6)
	r2 := newORig(t, orgOpts{})
	r2.as.ExpiresIn = 30
	r2.connect("bob")
	r2.as.OmitScope = true
	r2.as.NoRefreshToken = true
	r2.tokenOf("bob")
	g, _ := r2.store.Get(context.Background(), bobKey)
	if g.Scope != "read" || len(g.SealedRefresh) == 0 {
		t.Fatalf("%+v", g)
	}
}

func TestTokenResponsesAreValidated(t *testing.T) {
	cases := map[string]struct {
		mod    func(r *orig)
		want   int
		reason string
	}{
		"a lower case bearer is a bearer": {func(r *orig) { r.as.TokenType = "bearer" }, 200, ""},
		"a token of another type":         {func(r *orig) { r.as.TokenType = "MAC" }, 502, "token_response_invalid"},
		"no expires_in: no expiry known":  {func(r *orig) { r.as.ExpiresIn = -1 }, 200, ""},
		"a server error":                  {func(r *orig) { r.as.TokenError = 500 }, 502, ""},
	}
	for name, c := range cases {
		r := newORig(t, orgOpts{})
		c.mod(r)
		code, m := r.connect("bob")
		if code != c.want || (c.reason != "" && m["reason"] != c.reason) {
			t.Errorf("%s: %d %v", name, code, m)
		}
	}
	// scope omitted: RFC 6749 section 5.1, it is what was requested
	r := newORig(t, orgOpts{})
	r.as.OmitScope = true
	r.connect("bob")
	if g, _ := r.store.Get(context.Background(), bobKey); g.Scope != "read" {
		t.Fatalf("%+v", g)
	}
	// no expiry known: used as it is, and a 401 is what renews it
	r = newORig(t, orgOpts{})
	r.as.ExpiresIn = -1
	r.connect("bob")
	if g, _ := r.store.Get(context.Background(), bobKey); !g.AccessExpires.IsZero() {
		t.Fatalf("%+v", g)
	}
	w, m := r.call("notes", "acme", "bob", "whoami")
	if text(result(t, w, m)) != "token of bob" || r.as.Count("/token", "refresh_token") != 0 {
		t.Fatalf("%s", w.Body)
	}
}

// PATH O item 5 and the plan's table, "authorization server mix-up": the callback's iss must be the pinned issuer.
func TestAWrongOrMissingIssInTheCallbackFailsTheAuthorizationBeforeAnyCodeIsSpent(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.as.IssParameter = true
	r.as.WrongIss = "https://evil.example.com"
	code, m := r.connect("bob")
	if code != 400 || m["error"] != "authorization_failed" || m["reason"] != "iss_mismatch" {
		t.Fatalf("%d %v", code, m)
	}
	if r.as.Count("/token", "") != 0 {
		t.Fatal("the code was sent to the token endpoint")
	}
	if _, err := r.store.Get(context.Background(), bobKey); err == nil {
		t.Fatal("a grant was made")
	}
	// the server says it sends iss and does not
	r.as.WrongIss, r.as.OmitIss = "", "true"
	r.as.IssParameter = true
	if code, m = r.connect("bob"); code != 400 || m["reason"] != "iss_missing" {
		t.Fatalf("%d %v", code, m)
	}
	// an honest iss: fine
	r.as.OmitIss = ""
	if code, m = r.connect("bob"); code != 200 {
		t.Fatalf("%d %v", code, m)
	}
	// a server that does not advertise iss and sends none: fine (RFC 9207 requires it only where advertised)
	r2 := newORig(t, orgOpts{})
	if code, m = r2.connect("bob"); code != 200 {
		t.Fatalf("%d %v", code, m)
	}
}

func TestAnErrorFromTheAuthorizationServerIsAFixedCodeAndItsDescriptionNeverReachesTheMember(t *testing.T) {
	r := newORig(t, orgOpts{})
	for given, want := range map[string]string{"access_denied": "access_denied", "invalid_scope": "invalid_scope", "temporarily_unavailable": "temporarily_unavailable", "<script>": "authorization_failed"} {
		r.as.AuthError = given
		code, m := r.connect("bob")
		if code != 400 || m["error"] != "authorization_denied" || m["reason"] != want {
			t.Errorf("%s: %d %v", given, code, m)
		}
	}
	if r.as.Count("/token", "") != 0 {
		t.Fatal("the token endpoint was asked after an error")
	}
	for _, s := range r.seen {
		if strings.Contains(s, "secret detail") || strings.Contains(s, "script") {
			t.Fatalf("the server's words reached the member: %s", s)
		}
	}
}

func TestACallbackIsOneUseShortLivedAndForTheConnectionThatWasStarted(t *testing.T) {
	r := newORig(t, orgOpts{yaml: func(r *orig) string {
		return defaultYAML(r) + `
  - id: crm
    title: CRM
    endpoint: ` + r.tp.URL() + `
    authorization:
      mode: oauth
      issuer: ` + r.as.Issuer() + `
      client: {mode: cimd, document: "` + r.doc.URL + `/clients/crm.json"}
`
	}})
	start := func(member, conn string) map[string]string {
		_, m := r.callAPI("POST", "/"+conn+"/authorization", member, "")
		back, _ := asdoubleConsent(t, m["url"].(string), member)
		return map[string]string{"code": back.Get("code"), "state": back.Get("state")}
	}
	post := func(tenant, member, conn string, b map[string]string) int {
		body, _ := json.Marshal(b)
		code, _ := r.callAPIAs("POST", "/"+conn+"/callback", tenant, member, string(body))
		return code
	}
	// one use
	b := start("bob", "notes")
	if post("acme", "bob", "notes", b) != 200 || post("acme", "bob", "notes", b) != 400 {
		t.Fatal("a state worked twice, or not once")
	}
	// another tenant's member of the same name is another member, and does not use it up
	b = start("bob", "notes")
	if post("other", "bob", "notes", b) != 400 || post("acme", "bob", "notes", b) != 200 {
		t.Fatal("the state of one tenant's bob was usable by another's, or was used up by the attempt")
	}
	// the page says another connection than the one that was started: refused
	b = start("bob", "notes")
	if post("acme", "bob", "crm", b) != 400 {
		t.Fatal("a state of one connection finished another")
	}
	if post("acme", "bob", "notes", b) != 400 {
		t.Fatal("the refused state was left to be used")
	}
	// ten minutes
	b = start("bob", "notes")
	r.svc.Now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if post("acme", "bob", "notes", b) != 400 {
		t.Fatal("an expired state was accepted")
	}
	r.svc.Now = nil
	// a state that was never made, and the sweep of the ones that expired
	if post("acme", "bob", "notes", map[string]string{"state": "nonsense", "code": "x"}) != 400 {
		t.Fatal("a made-up state")
	}
	b = start("bob", "notes")
	r.svc.Now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if n, err := r.svc.Sweep(context.Background()); err != nil || n < 1 {
		t.Fatalf("%d %v", n, err)
	}
	r.svc.Now = nil
	if post("acme", "bob", "notes", b) != 400 {
		t.Fatal("a swept state")
	}
	// the error answers carry a code and nothing else
	code, m := r.callAPI("POST", "/notes/callback", "bob", `{"state":"x","code":"y"}`)
	if code != 400 || m["error"] != "invalid_state" {
		t.Fatalf("%d %v", code, m)
	}
}

func TestAMemberLosesNothingWhenSomeoneElseTriesTheirState(t *testing.T) {
	r := newORig(t, orgOpts{})
	_, m := r.callAPI("POST", "/notes/authorization", "bob", "")
	back, _ := asdoubleConsent(t, m["url"].(string), "bob")
	body, _ := json.Marshal(map[string]string{"code": back.Get("code"), "state": back.Get("state")})
	for i := 0; i < 3; i++ {
		if code, _ := r.callAPI("POST", "/notes/callback", "mallory", string(body)); code != 400 {
			t.Fatal("mallory finished bob's authorization")
		}
	}
	if code, _ := r.callAPI("POST", "/notes/callback", "bob", string(body)); code != 200 {
		t.Fatal("bob's own state was used up by mallory's attempts")
	}
	if _, err := r.store.Get(context.Background(), grants.Key{Tenant: "acme", Member: "mallory", Connection: "notes"}); err == nil {
		t.Fatal("mallory has a grant")
	}
}

func TestTheClientMetadataDocumentIsBuiltFromTheConfigurationAndTheServerFetchesIt(t *testing.T) {
	r := newORig(t, orgOpts{})
	code, doc := r.callAPI("GET", "/notes/client-metadata", "", "")
	req := httptest.NewRequest("GET", "/internal/v1/connections/notes/client-metadata", nil)
	w := httptest.NewRecorder()
	r.api.ServeHTTP(w, req) // no token
	_ = code
	_ = doc
	var d map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &d)
	if w.Code != 200 || d["client_id"] != r.doc.URL+"/clients/notes.json" || d["token_endpoint_auth_method"] != "none" ||
		asJSON(d["redirect_uris"]) != `["`+redirectURI+`"]` || asJSON(d["grant_types"]) != `["authorization_code","refresh_token"]` || asJSON(d["response_types"]) != `["code"]` || d["client_name"] != "Notes" {
		t.Fatalf("%d %v", w.Code, d)
	}
	for _, id := range []string{"svc", "nope"} {
		w := httptest.NewRecorder()
		r.api.ServeHTTP(w, httptest.NewRequest("GET", "/internal/v1/connections/"+id+"/client-metadata", nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", id, w.Code)
		}
	}
	// the authorization server fetched the document, found its own client_id and the redirect address, and the flow works
	if c, m := r.connect("bob"); c != 200 {
		t.Fatalf("%d %v", c, m)
	}
	tok := r.as.Requests("/token")[0]
	if tok.Form.Get("client_id") != r.doc.URL+"/clients/notes.json" || tok.Form.Get("client_secret") != "" || tok.Header.Get("Authorization") != "" ||
		tok.Form.Get("code_verifier") == "" || tok.Form.Get("redirect_uri") != redirectURI || tok.Form.Get("resource") != r.tp.URL() {
		t.Fatalf("%v %v", tok.Form, tok.Header)
	}
}

func TestWithoutCIMDSupportAConnectionNeedsDynamicRegistrationOptedInOrItIsRefused(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.as.CIMD, r.as.Registration = false, true
	code, m := r.callAPI("POST", "/notes/authorization", "bob", "")
	if code != 409 || m["reason"] != "client_identity_unsupported" || len(r.as.Requests("/register")) != 0 {
		t.Fatalf("%d %v, %d registrations", code, m, len(r.as.Requests("/register")))
	}
	// opted in: registered once, stored, the secret sealed, used with the method the server assigned
	r = newORig(t, orgOpts{yaml: func(r *orig) string {
		return strings.Replace(defaultYAML(r), `client: {mode: cimd, document:`, `client: {mode: cimd, dynamicRegistration: true, document:`, 1)
	}, mod: func(r *orig) { r.as.CIMD, r.as.Registration = false, true }})
	if c, m := r.connect("bob"); c != 200 {
		t.Fatalf("%d %v", c, m)
	}
	if c, m := r.connect("alice"); c != 200 {
		t.Fatalf("%d %v", c, m)
	}
	if n := len(r.as.Requests("/register")); n != 1 {
		t.Fatalf("%d registrations: one per connection", n)
	}
	reg, err := r.store.GetRegistration(context.Background(), "notes", r.as.Issuer(), redirectURI)
	if err != nil || !strings.HasPrefix(reg.ClientID, "dcr-") || len(reg.SealedSecret) == 0 || bytes.Contains(reg.SealedSecret, []byte(r.as.Registry[reg.ClientID])) {
		t.Fatalf("%+v %v", reg, err)
	}
	tok := r.as.Requests("/token")[0]
	if tok.Form.Get("client_secret") != r.as.Registry[reg.ClientID] || tok.Form.Get("client_id") != reg.ClientID {
		t.Fatalf("%v", tok.Form)
	}
	r.noSecretsAnywhere()
}

func TestAPreregisteredClientAuthenticatesWithTheMethodTheServerAdvertises(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("s3cret value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := func(r *orig) string {
		return `
connections:
  - id: notes
    title: Notes
    endpoint: ` + r.tp.URL() + `
    authorization:
      mode: oauth
      issuer: ` + r.as.Issuer() + `
      client: {mode: preregistered, id: "bridge-1", secretFile: ` + secret + `}
      scopes: [read]
`
	}
	for _, c := range []struct {
		name    string
		methods []string
		method  string
		want    string // "basic", "post" or "refused"
	}{
		{"no list: client_secret_basic is the default (RFC 8414)", nil, "client_secret_basic", "basic"},
		{"basic advertised", []string{"client_secret_post", "client_secret_basic"}, "client_secret_basic", "basic"},
		{"only post", []string{"client_secret_post"}, "client_secret_post", "post"},
		{"neither", []string{"private_key_jwt"}, "client_secret_basic", "refused"},
	} {
		r := newORig(t, orgOpts{yaml: yaml, mod: func(r *orig) {
			r.as.AuthMethods, r.as.Method = c.methods, c.method
			r.as.Preregister("bridge-1", "s3cret value")
		}})
		code, m := r.connect("bob")
		if c.want == "refused" {
			if code != 409 || m["reason"] != "client_identity_unsupported" {
				t.Errorf("%s: %d %v", c.name, code, m)
			}
			continue
		}
		if code != 200 {
			t.Errorf("%s: %d %v", c.name, code, m)
			continue
		}
		tok := r.as.Requests("/token")[0]
		hasBasic := strings.HasPrefix(tok.Header.Get("Authorization"), "Basic ")
		if (c.want == "basic") != hasBasic || (c.want == "post") != (tok.Form.Get("client_secret") == "s3cret value") {
			t.Errorf("%s: %v %v", c.name, tok.Header, tok.Form)
		}
		if q := query(r.as.Requests("/authorize")[0].Form.Get("redirect_uri")); q == nil {
			t.Error("no redirect")
		}
		r.noSecretsAnywhere("s3cret value")
	}
}

func asdoubleConsent(t *testing.T, authURL, user string) (url.Values, error) {
	t.Helper()
	v, err := asdouble.Consent(authURL, user)
	if err != nil {
		t.Fatal(err)
	}
	return v, nil
}

var _ = auth.ErrNoToken
