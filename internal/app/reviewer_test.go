package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"idp-mcp-bridge/internal/auth"
	"idp-mcp-bridge/internal/grants"
	"idp-mcp-bridge/internal/oauth"
)

var reviewerGrantKey = grants.Key{Connection: "notes", Reviewer: true}

func (r *orig) reviewerToken() string {
	r.t.Helper()
	tok, err := oauth.ReviewerSource{S: r.svc}.Token(context.Background(), "notes")
	if err != nil {
		r.t.Fatal(err)
	}
	return tok
}

// Plan section 2, item 8 (ADR-0001 D33): an operator authorizes a dedicated account at the third party once; the grant is the
// connection's, sealed, and what the gateway's listing goes out with.
func TestAnOperatorAuthorizesTheConnectionsReviewerAccountAndTheListingUsesItsToken(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		// without a reviewer account the third party wants a token for the listing, and the answer says what is missing
		w, m := r.list("notes")
		if w.Code != http.StatusBadGateway || !strings.Contains(asJSON(m["error"]), "reviewer account") {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		// the operator's authorization asks for the reviewer's scope, the least that lists the tools
		code, m := r.callAPIReviewer("POST", "/notes/reviewer/authorization", "ops", "")
		if code != 200 || query(m["url"].(string)).Get("scope") != "list" {
			t.Fatalf("%d %v", code, m)
		}
		if code, m = r.authorizeReviewer("ops"); code != 200 || m["status"] != "connected" {
			t.Fatalf("%d %v", code, m)
		}
		// stored as the connection's reviewer grant, sealed for it, and not as the operator's own member grant
		g, err := r.store.Get(context.Background(), reviewerGrantKey)
		if err != nil || !g.Reviewer || g.Tenant != "" || g.Member != "" || g.AuthorizedBy != "acme/ops" || g.Scope != "list" {
			t.Fatalf("%+v %v", g, err)
		}
		if _, err := r.store.Get(context.Background(), grants.Key{Tenant: "acme", Member: "ops", Connection: "notes"}); !errors.Is(err, grants.ErrNotFound) {
			t.Fatal("the operator was given a member grant")
		}
		member := reviewerGrantKey
		member.Reviewer = false
		if _, err := r.keys.Open(g.SealedAccess, member); err == nil {
			t.Fatal("the reviewer's token opens as a member's")
		}
		tok := r.reviewerToken()
		// the gateway's listing, which has no member, goes out with the reviewer's token
		w, m = r.list("notes")
		if tools := result(t, w, m)["tools"].([]any); len(tools) == 0 {
			t.Fatalf("%s", w.Body)
		}
		reqs := r.tp.Requests()
		if last := reqs[len(reqs)-1]; last.Method != "tools/list" || last.Header.Get("Authorization") != "Bearer "+tok {
			t.Fatalf("%+v", last.Header)
		}
		r.noSecretsAnywhere(tok)
	})
}

func TestOnlyACallerWithTheReviewerRoleMayAuthorizeOrDisconnectAReviewerAccount(t *testing.T) {
	r := newORig(t, orgOpts{})
	for _, c := range []struct{ method, path string }{{"POST", "/notes/reviewer/authorization"}, {"DELETE", "/notes/reviewer/grant"}} {
		if code, m := r.callAPI(c.method, c.path, "ops", ""); code != 403 || m["error"] != "forbidden" {
			t.Errorf("%s %s: %d %v", c.method, c.path, code, m)
		}
	}
	if code, _ := r.callAPIReviewer("POST", "/svc/reviewer/authorization", "ops", ""); code != 404 {
		t.Errorf("a connection that needs no token has no reviewer account: %d", code)
	}
	if code, _ := r.callAPIReviewer("POST", "/nope/reviewer/authorization", "ops", ""); code != 404 {
		t.Errorf("%d", code)
	}
	if r.store.(*grants.Memory).States() != 0 {
		t.Fatal("a refused call left an authorization pending")
	}
	// the role is checked again at the callback: taken away since the start, the authorization is not finished
	_, m := r.callAPIReviewer("POST", "/notes/reviewer/authorization", "ops", "")
	back, _ := asdoubleConsent(t, m["url"].(string), "reviewer-account")
	body, _ := json.Marshal(map[string]string{"code": back.Get("code"), "state": back.Get("state")})
	if code, m := r.callAPI("POST", "/notes/callback", "ops", string(body)); code != 403 || m["error"] != "forbidden" {
		t.Fatalf("%d %v", code, m)
	}
	if _, err := r.store.Get(context.Background(), reviewerGrantKey); err == nil {
		t.Fatal("a reviewer grant was made without the role")
	}
}

// The state of a reviewer authorization is bound to the operator who started it, as any state is.
func TestAReviewerAuthorizationIsFinishedByTheOperatorWhoStartedItAndNoOneElse(t *testing.T) {
	r := newORig(t, orgOpts{})
	_, m := r.callAPIReviewer("POST", "/notes/reviewer/authorization", "ops", "")
	back, _ := asdoubleConsent(t, m["url"].(string), "reviewer-account")
	body, _ := json.Marshal(map[string]string{"code": back.Get("code"), "state": back.Get("state")})
	if code, _ := r.callAPIReviewer("POST", "/notes/callback", "other-ops", string(body)); code != 400 {
		t.Fatalf("another operator finished it: %d", code)
	}
	if code, _ := r.callAPIReviewer("POST", "/notes/callback", "ops", string(body)); code != 200 {
		t.Fatal("the operator's own state was used up by the other's attempt")
	}
	// and a state of a member's authorization never ends in a reviewer grant
	r2 := newORig(t, orgOpts{})
	if code, _ := r2.connectAs("acme", "ops", "notes"); code != 200 {
		t.Fatal(code)
	}
	if _, err := r2.store.Get(context.Background(), reviewerGrantKey); err == nil {
		t.Fatal("a member's authorization made the reviewer grant")
	}
}

// The reviewer's token is for tools/list and never for a tools/call: a member without a grant is told to connect while a reviewer
// grant exists, and a member with one calls with their own token.
func TestTheReviewerTokenIsNeverUsedForACallAndTheMembersGrantIsIndependentOfIt(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		if code, m := r.authorizeReviewer("ops"); code != 200 {
			t.Fatalf("%d %v", code, m)
		}
		rtok := r.reviewerToken()
		before := len(r.tp.Requests())
		for _, member := range []string{"alice", "ops"} { // ops authorized the reviewer account, and has no grant of their own
			w, m := r.call("notes", "acme", member, "whoami")
			if res := result(t, w, m); !r.authRequired(res) {
				t.Fatalf("%s: %s", member, w.Body)
			}
		}
		if len(r.tp.Requests()) != before {
			t.Fatal("a call went out for a member who has not connected, because a reviewer grant exists")
		}
		// ops connects as a member too: two grants of the same person on the same connection, independent
		if code, m := r.connectAs("acme", "ops", "notes"); code != 200 {
			t.Fatalf("%d %v", code, m)
		}
		mtok := r.tokenOf("ops")
		if mtok == rtok {
			t.Fatal("the member's token is the reviewer's")
		}
		w, m := r.call("notes", "acme", "ops", "whoami")
		if res := result(t, w, m); text(res) != "token of ops" {
			t.Fatalf("%s", w.Body)
		}
		for _, c := range r.tp.Calls() {
			if c.Header.Get("Authorization") != "Bearer "+mtok {
				t.Fatalf("a call carried %q, not the member's token", c.Header.Get("Authorization"))
			}
		}
		// disconnecting one leaves the other
		if code, _ := r.callAPI("DELETE", "/notes/grant", "ops", ""); code != 204 {
			t.Fatal(code)
		}
		if _, err := r.store.Get(context.Background(), reviewerGrantKey); err != nil {
			t.Fatal("the member's disconnect removed the reviewer grant")
		}
		r.connectAs("acme", "ops", "notes")
		if code, _ := r.callAPIReviewer("DELETE", "/notes/reviewer/grant", "ops", ""); code != 204 {
			t.Fatal(code)
		}
		if _, err := r.store.Get(context.Background(), grants.Key{Tenant: "acme", Member: "ops", Connection: "notes"}); err != nil {
			t.Fatal("the reviewer's disconnect removed the member's grant")
		}
		if _, err := r.store.Get(context.Background(), reviewerGrantKey); !errors.Is(err, grants.ErrNotFound) {
			t.Fatal("the reviewer grant is still there")
		}
	})
}

func TestTheListShowsTheReviewerAccountToACallerWithTheRoleOnly(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.authorizeReviewer("ops")
	byID := func(m map[string]any) map[string]map[string]any {
		out := map[string]map[string]any{}
		for _, c := range m["connections"].([]any) {
			e := c.(map[string]any)
			out[e["id"].(string)] = e
		}
		return out
	}
	_, mm := r.callAPI("GET", "", "ops", "")
	for id, e := range byID(mm) {
		if _, has := e["reviewer"]; has {
			t.Errorf("%s: a member sees the reviewer account: %v", id, e)
		}
	}
	if strings.Contains(asJSON(mm), "reviewer") {
		t.Fatalf("%v", mm)
	}
	_, rm := r.callAPIReviewer("GET", "", "ops", "")
	e := byID(rm)
	if rv := e["notes"]["reviewer"].(map[string]any); rv["status"] != "connected" || rv["scope"] != "list" {
		t.Fatalf("%v", e["notes"])
	}
	if rv := e["svc"]["reviewer"].(map[string]any); rv["status"] != "not_required" {
		t.Fatalf("%v", e["svc"])
	}
	// the reviewer's state does not show as the operator's own connection
	if e["notes"]["status"] != "not_connected" {
		t.Fatalf("%v", e["notes"])
	}
	// a reviewer grant that cannot be used says why, as a member's does
	g, _ := r.store.Get(context.Background(), reviewerGrantKey)
	g.Issuer = "https://old.example.com"
	_ = r.store.Put(context.Background(), g)
	_, rm = r.callAPIReviewer("GET", "", "ops", "")
	if rv := byID(rm)["notes"]["reviewer"].(map[string]any); rv["status"] != "reauthorization_required" || rv["reason"] != "issuer_changed" {
		t.Fatalf("%v", rv)
	}
	g.Issuer = r.as.Issuer()
	_ = r.store.Put(context.Background(), g)
	if _, rm = r.callAPIReviewer("GET", "", "nobody", ""); byID(rm)["notes"]["reviewer"].(map[string]any)["status"] != "connected" {
		t.Fatal("the reviewer account is the connection's: every operator with the role sees the same one")
	}
	r.noSecretsAnywhere()
}

func TestTheReviewerTokenIsRenewedLikeAMembersUnderTheSameLockAndRotation(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		r.as.ExpiresIn = 30
		r.as.Rotate = true
		r.authorizeReviewer("ops")
		r.as.ExpiresIn = 3600
		r.as.TokenDelay = 100 * time.Millisecond
		second := *r.svc
		second.Store = r.open()
		var wg sync.WaitGroup
		toks := make([]string, 6)
		for i := range toks {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s := r.svc
				if i%2 == 1 {
					s = &second
				}
				toks[i], _ = oauth.ReviewerSource{S: s}.Token(context.Background(), "notes")
			}()
		}
		wg.Wait()
		for _, tk := range toks {
			if tk == "" || tk != toks[0] {
				t.Fatalf("%v", toks)
			}
		}
		if n := r.as.Count("/token", "refresh_token"); n != 1 {
			t.Fatalf("the reviewer's refresh token was spent %d times", n)
		}
		// 401 on the listing: one renewal, one retry
		r.as.TokenDelay = 0
		n := r.as.Count("/token", "refresh_token")
		r.as.ExpireAll()
		w, m := r.list("notes")
		if tools := result(t, w, m)["tools"].([]any); len(tools) == 0 || r.as.Count("/token", "refresh_token") != n+1 {
			t.Fatalf("%s (%d refreshes)", w.Body, r.as.Count("/token", "refresh_token"))
		}
		// a refresh token the server refuses deletes the reviewer grant: the listing goes without a token again
		r.as.InvalidGrant = true
		r.as.ExpiresIn = 30
		r.as.InvalidateRefreshTokens()
		r.svc.Now = func() time.Time { return time.Now().Add(time.Hour) }
		_, _ = oauth.ReviewerSource{S: r.svc}.Token(context.Background(), "notes")
		r.svc.Now = nil
		if _, err := r.store.Get(context.Background(), reviewerGrantKey); !errors.Is(err, grants.ErrNotFound) {
			t.Fatalf("%v", err)
		}
		if _, err := (oauth.ReviewerSource{S: r.svc}).Token(context.Background(), "notes"); !errors.Is(err, auth.ErrNoToken) {
			t.Fatalf("%v", err)
		}
	})
}

func TestDisconnectingTheReviewerAccountRevokesItsTokensAtTheServer(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.as.Revocation = true
	r.authorizeReviewer("ops")
	tok := r.reviewerToken()
	if code, _ := r.callAPIReviewer("DELETE", "/notes/reviewer/grant", "ops", ""); code != 204 {
		t.Fatal(code)
	}
	if !r.as.Revoked(tok) || len(r.as.Requests("/revoke")) != 2 {
		t.Fatalf("revoked %v, %d requests", r.as.Revoked(tok), len(r.as.Requests("/revoke")))
	}
	if code, _ := r.callAPIReviewer("DELETE", "/notes/reviewer/grant", "ops", ""); code != 204 {
		t.Fatal("disconnecting again is not an error")
	}
	// the operator offboarding a member does not remove the connection's reviewer account; withdrawing the connection does
	r.authorizeReviewer("ops")
	if n, _ := r.svc.RevokeMember(context.Background(), "acme", "ops", ""); n != 0 {
		t.Fatalf("%d", n)
	}
	if _, err := r.store.Get(context.Background(), reviewerGrantKey); err != nil {
		t.Fatal("RevokeMember removed the reviewer grant")
	}
	if n, _ := r.svc.RevokeConnection(context.Background(), "notes"); n != 1 {
		t.Fatalf("%d", n)
	}
}

func TestAReviewerAuthorizationUsesTheConnectionsScopesIfNoReviewerScopesAreGiven(t *testing.T) {
	r := newORig(t, orgOpts{yaml: func(r *orig) string {
		return strings.Replace(defaultYAML(r), "      reviewerScopes: [list]\n", "", 1)
	}})
	_, m := r.callAPIReviewer("POST", "/notes/reviewer/authorization", "ops", "")
	if query(m["url"].(string)).Get("scope") != "read" {
		t.Fatalf("%v", m)
	}
}
