package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"idp-mcp-bridge/internal/auth"
	"idp-mcp-bridge/internal/config"
	"idp-mcp-bridge/internal/grants"
	"idp-mcp-bridge/internal/oauth"
	"idp-mcp-bridge/internal/sealer"
)

// The plan's section 3, row "authorization server confusion, led to an attacker's server": the issuer is pinned, the resource
// vouches for it, and the metadata must name it, character for character; any mismatch is refused, says which, and is not followed.
func TestDiscoveryRefusesWhatDoesNotMatchThePinnedIssuerAndTheEndpoint(t *testing.T) {
	cases := []struct {
		name   string
		mod    func(r *orig)
		reason string
	}{
		{"the metadata names another issuer", func(r *orig) { r.as.MetadataIssuer = "https://evil.example.com" }, oauth.CodeIssuerMismatch},
		{"the same issuer with a trailing slash", func(r *orig) { r.as.MetadataIssuer = r.as.Issuer() + "/" }, oauth.CodeIssuerMismatch},
		{"the resource lists other authorization servers only", func(r *orig) {
			r.tp.PRM["authorization_servers"] = []string{"https://evil.example.com", r.as.Issuer() + "/"}
		}, oauth.CodeIssuerNotListed},
		{"the resource names another resource", func(r *orig) { r.tp.PRM["resource"] = "https://other.example.com/mcp" }, oauth.CodeResourceMismatch},
		{"the resource is the endpoint with a trailing slash", func(r *orig) { r.tp.PRM["resource"] = r.tp.URL() + "/" }, oauth.CodeResourceMismatch},
		{"the resource is a parent of the endpoint", func(r *orig) { r.tp.PRM["resource"] = strings.TrimSuffix(r.tp.URL(), "/mcp") }, oauth.CodeResourceMismatch},
		{"the challenge points the metadata at another origin", func(r *orig) {
			r.tp.Challenge = `Bearer resource_metadata="https://evil.example.com/.well-known/oauth-protected-resource"`
		}, oauth.CodePRMOrigin},
		{"no PKCE with S256", func(r *orig) { r.as.NoS256 = true }, oauth.CodePKCEUnsupported},
		{"an authorization endpoint that is not a public address", func(r *orig) { r.as.AuthEndpoint = "https://10.0.0.5/authorize" }, oauth.CodeAddressRefused},
		{"an authorization endpoint over http", func(r *orig) { r.as.AuthEndpoint = "http://login.example.com/authorize" }, oauth.CodeAddressRefused},
		{"metadata that redirects to another origin", func(r *orig) { r.as.RedirectMetadata = "https://evil.example.com/meta" }, oauth.CodeRedirectRefused},
		{"no protected resource metadata at all", func(r *orig) { r.tp.PRM = nil }, oauth.CodeMetadataInvalid},
	}
	for _, c := range cases {
		r := newORig(t, orgOpts{mod: c.mod})
		code, m := r.callAPI("POST", "/notes/authorization", "bob", "")
		if code != 409 || m["error"] != "authorization_server_refused" || m["reason"] != c.reason {
			t.Errorf("%s: %d %v", c.name, code, m)
		}
		if len(r.as.Requests("/authorize")) != 0 || len(r.as.Requests("/token")) != 0 {
			t.Errorf("%s: the member was sent on, or a token was asked for", c.name)
		}
		if r.store.(*grants.Memory).States() != 0 {
			t.Errorf("%s: an authorization was left pending", c.name)
		}
	}
}

func TestDiscoveryFollowsASameOriginRedirectThatKeepsTheMethodAndFindsTheMetadataByTheOtherNames(t *testing.T) {
	r := newORig(t, orgOpts{mod: func(r *orig) { r.as.RedirectMetadata = "same" }})
	if code, m := r.callAPI("POST", "/notes/authorization", "bob", ""); code != 200 {
		t.Fatalf("%d %v", code, m)
	}
	// the metadata candidates of an issuer with and without a path (RFC 8414 section 3, OpenID discovery)
	for _, c := range []struct{ issuer, want string }{
		{"https://a.example.com", "https://a.example.com/.well-known/oauth-authorization-server https://a.example.com/.well-known/openid-configuration"},
		{"https://a.example.com/realms/x", "https://a.example.com/.well-known/oauth-authorization-server/realms/x https://a.example.com/.well-known/openid-configuration/realms/x https://a.example.com/realms/x/.well-known/openid-configuration"},
	} {
		if got := strings.Join(oauth.MetadataURLs(c.issuer), " "); got != c.want {
			t.Errorf("%s: %s", c.issuer, got)
		}
	}
}

// The plan's section 3, row "token used for another service": the resource of RFC 8707 is in the authorization request, the
// code exchange and every refresh, and a grant is never found by another connection.
func TestATokenIsBoundToItsConnectionByTheResourceAndByTheGrantsKey(t *testing.T) {
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
	r.connect("bob")
	// bob's grant for notes is not a token for crm, in the source or at the third party
	if _, err := r.svc.Token(context.Background(), auth.Subject{Tenant: "acme", Member: "bob"}, "crm"); !errors.Is(err, auth.ErrNoToken) {
		t.Fatalf("%v", err)
	}
	before := len(r.tp.Calls())
	w, m := r.call("crm", "acme", "bob", "whoami")
	if res := result(t, w, m); res["isError"] != true || !strings.Contains(asJSON(res["structuredContent"]), `"connection":"crm"`) || len(r.tp.Calls()) != before {
		t.Fatalf("%s", w.Body)
	}

	// and the resource of RFC 8707 is in the authorization request, the code exchange and every refresh
	r.as.ExpiresIn = 30
	r.connect("bob")
	r.tokenOf("bob")
	for _, req := range []struct{ path, kind string }{{"/authorize", ""}, {"/token", "authorization_code"}, {"/token", "refresh_token"}} {
		found := false
		for _, q := range r.as.Requests(req.path) {
			if req.kind == "" || q.Form.Get("grant_type") == req.kind {
				found = true
				if q.Form.Get("resource") != r.tp.URL() {
					t.Errorf("%s %s: resource %q", req.path, req.kind, q.Form.Get("resource"))
				}
			}
		}
		if !found {
			t.Errorf("no %s %s request", req.path, req.kind)
		}
	}
}

// The plan's section 3, row "member A's call used member B's token": the token is looked up for the member the gateway signed.
func TestOneMembersCallNeverUsesAnotherMembersToken(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		r.connect("bob")
		bobTok := r.tokenOf("bob")
		before := len(r.tp.Requests())
		for _, who := range [][2]string{{"acme", "alice"}, {"other-tenant", "bob"}, {"acme", "bob "}, {"", "bob"}} {
			w, m := r.call("notes", who[0], who[1], "whoami")
			if res := result(t, w, m); !r.authRequired(res) {
				t.Errorf("%v: %s", who, w.Body)
			}
		}
		if len(r.tp.Requests()) != before {
			t.Fatal("the third party received a request for a member who has no token")
		}
		// a sealed row copied to another member's key does not open: the key binds it
		g, _ := r.store.Get(context.Background(), bobKey)
		g.Key = grants.Key{Tenant: "acme", Member: "alice", Connection: "notes"}
		if err := r.store.Put(context.Background(), g); err != nil {
			t.Fatal(err)
		}
		tok, err := r.svc.Token(context.Background(), auth.Subject{Tenant: "acme", Member: "alice"}, "notes")
		if err == nil || tok != "" || errors.Is(err, auth.ErrNoToken) {
			t.Fatalf("a token sealed for bob opened for alice: %q %v", tok, err)
		}
		w, m := r.call("notes", "acme", "alice", "whoami")
		res := result(t, w, m)
		if res["isError"] != true || r.authRequired(res) || strings.Contains(w.Body.String(), bobTok) || len(r.tp.Requests()) != before {
			t.Fatalf("%s", w.Body)
		}
		// the same for a row moved to another connection
		g.Key = grants.Key{Tenant: "acme", Member: "bob", Connection: "crm"}
		_ = r.store.Put(context.Background(), g)
		if _, err := r.keys.Open(g.SealedAccess, g.Key); !errors.Is(err, sealer.ErrOpen) {
			t.Fatalf("%v", err)
		}
		r.noSecretsAnywhere(bobTok)
	})
}

// Two replicas, one grant, a server that invalidates a refresh token when it rotates it: the token is spent once and the
// second caller uses the first one's result, whichever replica it is on (ADR-0001 D26).
func TestTwoCallersOnTwoReplicasSpendTheRefreshTokenOnce(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		r.as.ExpiresIn = 30
		r.as.Rotate = true
		if c, m := r.connect("bob"); c != 200 {
			t.Fatalf("%d %v", c, m)
		}
		r.as.ExpiresIn = 3600 // what the renewal issues lasts
		r.as.TokenDelay = 150 * time.Millisecond
		second := *r.svc
		second.Store = r.open() // another replica: another pool over the same rows
		var wg sync.WaitGroup
		toks := make([]string, 6)
		errs := make([]error, 6)
		for i := range toks {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s := r.svc
				if i%2 == 1 {
					s = &second
				}
				toks[i], errs[i] = s.Token(context.Background(), auth.Subject{Tenant: "acme", Member: "bob"}, "notes")
			}()
		}
		wg.Wait()
		for i := range toks {
			if errs[i] != nil || toks[i] == "" || toks[i] != toks[0] {
				t.Fatalf("caller %d: %q %v (first %q)", i, toks[i], errs[i], toks[0])
			}
		}
		if n := r.as.Count("/token", "refresh_token"); n != 1 {
			t.Fatalf("the refresh token was spent %d times", n)
		}
		if _, err := r.store.Get(context.Background(), bobKey); err != nil {
			t.Fatal("the grant was lost: a second use of a rotated refresh token is invalid_grant")
		}
	})
}

func TestARefreshTokenTheServerRefusesDeletesTheGrantAndTheMemberIsToldToConnect(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		r.as.ExpiresIn = 30
		r.connect("bob")
		r.as.InvalidGrant = true
		w, m := r.call("notes", "acme", "bob", "whoami")
		if res := result(t, w, m); !r.authRequired(res) {
			t.Fatalf("%s", w.Body)
		}
		if _, err := r.store.Get(context.Background(), bobKey); !errors.Is(err, grants.ErrNotFound) {
			t.Fatalf("the grant is still there: %v", err)
		}
		// and then connecting again works
		r.as.InvalidGrant = false
		r.as.ExpiresIn = 3600
		if c, _ := r.connect("bob"); c != 200 {
			t.Fatal("cannot connect again")
		}
	})
}

func TestAnAuthorizationServerThatDoesNotAnswerLeavesAValidTokenInUseAndTheGrantInPlace(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.as.ExpiresIn = 30
	r.connect("bob")
	r.as.TokenError = 503
	// inside the window but not expired: the renewal fails and the token that is still good is used
	w, m := r.call("notes", "acme", "bob", "whoami")
	if res := result(t, w, m); text(res) != "token of bob" {
		t.Fatalf("%s", w.Body)
	}
	// refused by the third party and not renewable just now: an error to try again, not "connect again"
	r.as.ExpireAll()
	w, m = r.call("notes", "acme", "bob", "whoami")
	if res := result(t, w, m); res["isError"] != true || r.authRequired(res) || !strings.Contains(text(res), "could not be") {
		t.Fatalf("%s", w.Body)
	}
	if _, err := r.store.Get(context.Background(), bobKey); err != nil {
		t.Fatal("the grant went with a server error")
	}
}

// Step-up (ADR-0001 D27): a 403 that says insufficient_scope is "authorization required"; one that does not is "refused".
func TestInsufficientScopeAsksTheMemberToAuthorizeAgainForTheUnionAndAPlain403IsJustRefused(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		r.connect("bob")
		// a 403 that is not insufficient_scope
		w, m := r.call("notes", "acme", "bob", "forbidden")
		if res := result(t, w, m); res["isError"] != true || r.authRequired(res) || !strings.Contains(text(res), "refused") {
			t.Fatalf("%s", w.Body)
		}
		if g, _ := r.store.Get(context.Background(), bobKey); g.ReauthReason != "" {
			t.Fatal("a plain 403 marked the grant")
		}
		// insufficient_scope
		w, m = r.call("notes", "acme", "bob", "write")
		if res := result(t, w, m); !r.authRequired(res) {
			t.Fatalf("%s", w.Body)
		}
		g, _ := r.store.Get(context.Background(), bobKey)
		if g.ReauthReason != "insufficient_scope" || g.NeededScope != "read write" || g.Scope != "read" {
			t.Fatalf("%+v", g)
		}
		// the grant is not used until the member authorizes again, and the list says why
		before := len(r.tp.Calls())
		w, m = r.call("notes", "acme", "bob", "whoami")
		if res := result(t, w, m); !r.authRequired(res) || len(r.tp.Calls()) != before {
			t.Fatalf("%s", w.Body)
		}
		_, list := r.callAPI("GET", "", "bob", "")
		if got := asJSON(list["connections"].([]any)[0]); !strings.Contains(got, `"status":"reauthorization_required"`) || !strings.Contains(got, `"reason":"insufficient_scope"`) {
			t.Fatalf("%s", got)
		}
		// the next authorization asks for the union
		if c, m := r.connect("bob"); c != 200 {
			t.Fatalf("%d %v", c, m)
		}
		reqs := r.as.Requests("/authorize")
		if sc := reqs[len(reqs)-1].Form.Get("scope"); sc != "read write" {
			t.Fatalf("asked for %q", sc)
		}
		w, m = r.call("notes", "acme", "bob", "write")
		if res := result(t, w, m); text(res) != "written by bob" {
			t.Fatalf("%s", w.Body)
		}
		if g, _ := r.store.Get(context.Background(), bobKey); g.ReauthReason != "" || g.Scope != "read write" {
			t.Fatalf("%+v", g)
		}
	})
}

// PATH O item 6.
func TestDisconnectingRevokesAtTheServerDeletesTheGrantAndTheNextCallAsksToConnectAndAFailedRevocationDoesNotKeepTheMemberConnected(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		r.as.Revocation = true
		r.connect("bob")
		tok, rt := r.tokenOf("bob"), r.as.RefreshTokenOf("bob")
		if code, _ := r.callAPI("DELETE", "/notes/grant", "bob", ""); code != 204 {
			t.Fatalf("%d", code)
		}
		if !r.as.Revoked(tok) || !r.as.Revoked(rt) {
			t.Fatal("the tokens were not revoked at the server")
		}
		revs := r.as.Requests("/revoke")
		if len(revs) != 2 || revs[0].Form.Get("token_type_hint") != "refresh_token" || revs[1].Form.Get("token_type_hint") != "access_token" {
			t.Fatalf("revocations in the wrong order: %+v", revs)
		}
		if _, err := r.store.Get(context.Background(), bobKey); !errors.Is(err, grants.ErrNotFound) {
			t.Fatal("the grant is still stored")
		}
		w, m := r.call("notes", "acme", "bob", "whoami")
		if res := result(t, w, m); !r.authRequired(res) {
			t.Fatalf("%s", w.Body)
		}
		// disconnecting again is not an error
		if code, _ := r.callAPI("DELETE", "/notes/grant", "bob", ""); code != 204 {
			t.Fatalf("%d", code)
		}
		// the server's revocation endpoint is down: deleted all the same, and only the code is logged
		r.connect("bob")
		r.as.RevokeStatus = 503
		if code, _ := r.callAPI("DELETE", "/notes/grant", "bob", ""); code != 204 {
			t.Fatalf("%d", code)
		}
		if _, err := r.store.Get(context.Background(), bobKey); !errors.Is(err, grants.ErrNotFound) {
			t.Fatal("a failed revocation kept the member connected")
		}
		if !strings.Contains(r.log.String(), "revocation failed") {
			t.Fatal("the failure was not logged")
		}
		r.noSecretsAnywhere(tok, rt)
	})
}

func TestTheListShowsEachConnectionsStatusForTheMemberAndNoTokenAndNoAddress(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.connect("bob")
	statuses := func(member string) map[string]map[string]any {
		_, m := r.callAPI("GET", "", member, "")
		out := map[string]map[string]any{}
		for _, c := range m["connections"].([]any) {
			e := c.(map[string]any)
			out[e["id"].(string)] = e
		}
		return out
	}
	alice, bob := statuses("alice"), statuses("bob")
	if alice["svc"]["status"] != "not_required" || alice["notes"]["status"] != "not_connected" || alice["notes"]["title"] != "Notes" {
		t.Fatalf("%v", alice)
	}
	if bob["notes"]["status"] != "connected" || bob["notes"]["scope"] != "read" {
		t.Fatalf("%v", bob)
	}
	// issuer changed since, and expired with nothing to renew it with
	g, _ := r.store.Get(context.Background(), bobKey)
	g.Issuer = "https://old.example.com"
	_ = r.store.Put(context.Background(), g)
	if e := statuses("bob")["notes"]; e["status"] != "reauthorization_required" || e["reason"] != "issuer_changed" {
		t.Fatalf("%v", e)
	}
	g.Issuer, g.SealedRefresh, g.AccessExpires = r.as.Issuer(), nil, time.Now().Add(-time.Minute)
	_ = r.store.Put(context.Background(), g)
	if e := statuses("bob")["notes"]; e["status"] != "reauthorization_required" || e["reason"] != "expired" {
		t.Fatalf("%v", e)
	}
	_, raw := r.callAPI("GET", "", "bob", "")
	for _, s := range append(r.as.Secrets(), "127.0.0.1", r.as.Issuer(), "authorize", "token") {
		if strings.Contains(asJSON(raw), s) {
			t.Errorf("the list holds %q", s)
		}
	}
	// the grant that cannot be used is not used
	if _, err := r.svc.Token(context.Background(), auth.Subject{Tenant: "acme", Member: "bob"}, "notes"); !errors.Is(err, auth.ErrNoToken) {
		t.Fatalf("%v", err)
	}
}

// The grants are sealed under the key of the moment: a rotation is new rows and refreshes under the new key, old rows still
// open, and `reseal` moves the rest.
func TestKeyRotationNewRowsUseTheCurrentKeyOldRowsStillOpenAndResealMovesTheRest(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		r.as.ExpiresIn = 30
		r.connect("bob") // under k1
		g, _ := r.store.Get(context.Background(), bobKey)
		if id, _ := sealer.KeyID(g.SealedAccess); id != "k1" {
			t.Fatal(id)
		}
		r.svc.Sealer = testKeys(t, "k2", "k1") // rotated: k2 seals, k1 still opens
		r.as.ExpiresIn = 3600
		if _, err := r.svc.Token(context.Background(), auth.Subject{Tenant: "acme", Member: "bob"}, "notes"); err != nil {
			t.Fatalf("a row of the old key did not open: %v", err) // and this renewed it
		}
		g, _ = r.store.Get(context.Background(), bobKey)
		if a, _ := sealer.KeyID(g.SealedAccess); a != "k2" {
			t.Fatalf("a refresh sealed under %s", a)
		}
		r.connectAs("acme", "carol", "notes") // new rows: the current key
		cg, _ := r.store.Get(context.Background(), grants.Key{Tenant: "acme", Member: "carol", Connection: "notes"})
		if id, _ := sealer.KeyID(cg.SealedAccess); id != "k2" {
			t.Fatal(id)
		}
		// an old row: put one back under k1, then reseal
		old, _ := testKeys(t, "k1").Seal([]byte("plain"), bobKey)
		g.SealedAccess = old
		_ = r.store.Put(context.Background(), g)
		n, err := oauth.Reseal(context.Background(), r.svc.Sealer.(*sealer.Keys), r.store)
		if err != nil || n != 1 {
			t.Fatalf("%d %v", n, err)
		}
		g, _ = r.store.Get(context.Background(), bobKey)
		if id, _ := sealer.KeyID(g.SealedAccess); id != "k2" {
			t.Fatal(id)
		}
		if pt, err := testKeys(t, "k2").Open(g.SealedAccess, bobKey); err != nil || string(pt) != "plain" {
			t.Fatalf("%q %v", pt, err)
		}
		// with k1 gone from the file, a row still under it does not open, and says so
		if _, err := testKeys(t, "k2").Open(old, bobKey); !errors.Is(err, sealer.ErrUnknownKey) {
			t.Fatalf("%v", err)
		}
	})
}

func TestTheOperatorRevokesAMembersGrantsOrAConnectionsAndAnAutomaticOffboardingIsNotPretended(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.as.Revocation = true
	for _, m := range []string{"bob", "carol"} {
		r.connect(m)
	}
	rt := r.as.RefreshTokenOf("bob")
	n, err := r.svc.RevokeMember(context.Background(), "acme", "bob", "")
	if err != nil || n != 1 || !r.as.Revoked(rt) {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := r.store.Get(context.Background(), bobKey); err == nil {
		t.Fatal("bob's grant is still there")
	}
	if _, err := r.store.Get(context.Background(), grants.Key{Tenant: "acme", Member: "carol", Connection: "notes"}); err != nil {
		t.Fatal("carol's grant went with bob's")
	}
	if n, err = r.svc.RevokeMember(context.Background(), "acme", "carol", "another"); err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
	if n, err = r.svc.RevokeConnection(context.Background(), "notes"); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestNothingSecretIsAnywhereAfterEveryKindOfFailure(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.as.Revocation = true
	r.as.ExpiresIn = 30
	r.connect("bob")
	r.as.IssParameter, r.as.WrongIss = true, "https://evil.example.com"
	r.connect("bob")
	r.as.IssParameter, r.as.WrongIss, r.as.AuthError = false, "", "access_denied"
	r.connect("bob")
	r.as.AuthError = ""
	r.as.TokenError = 500
	r.connect("bob") // the code is refused by a failing token endpoint
	r.call("notes", "acme", "bob", "whoami")
	r.as.TokenError = 0
	r.as.InvalidGrant = true
	r.call("notes", "acme", "bob", "whoami")
	r.callAPI("POST", "/notes/callback", "bob", `{"state":"a","code":"SECRETCODE","iss":"x"}`)
	r.noSecretsAnywhere("SECRETCODE")
	if !bytes.Contains(r.log.Bytes(), []byte("code")) {
		t.Fatal("nothing was logged: the search above proves nothing")
	}
}

// What is stored with a pending authorization is what was true when it started: a configuration that changed since is refused.
func TestAnAuthorizationStartedUnderAnotherConfigurationIsNotFinished(t *testing.T) {
	r := newORig(t, orgOpts{})
	_, m := r.callAPI("POST", "/notes/authorization", "bob", "")
	back, _ := asdoubleConsent(t, m["url"].(string), "bob")
	r.svc.Connections = append([]config.Connection(nil), r.svc.Connections...)
	r.svc.Connections[0].Authorization.Issuer = "https://another.example.com"
	body, _ := json.Marshal(map[string]string{"code": back.Get("code"), "state": back.Get("state")})
	if code, m := r.callAPI("POST", "/notes/callback", "bob", string(body)); code != 409 || m["error"] != "configuration_changed" || r.as.Count("/token", "") != 0 {
		t.Fatalf("%d %v", code, m)
	}
}
