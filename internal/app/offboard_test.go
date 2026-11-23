package app

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"idp-mcp-bridge/internal/api"
	"idp-mcp-bridge/internal/auth"
	"idp-mcp-bridge/internal/directory"
	"idp-mcp-bridge/internal/grants"
	"idp-mcp-bridge/internal/reconcile"
)

func (r *orig) offboard(bearer, body string) (int, map[string]any) {
	req := httptest.NewRequest("POST", "/internal/v1/members/offboard", strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	r.api.ServeHTTP(w, req)
	r.record(w.Body.String())
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m
}

func offboardBody(tenant, member, reason string) string {
	b, _ := json.Marshal(map[string]string{"tenant": tenant, "member": member, "reason": reason})
	return string(b)
}

func twoOAuthConnections(r *orig) string {
	return defaultYAML(r) + `
  - id: crm
    title: CRM
    endpoint: ` + r.tp.URL() + `
    authorization:
      mode: oauth
      issuer: ` + r.as.Issuer() + `
      client: {mode: cimd, document: "` + r.doc.URL + `/clients/crm.json"}
`
}

// ADR-0001 D38: a service tells the bridge a member left; everything the bridge holds for the member goes, the tokens are revoked at
// the third party first where it can be done, and the answer is counts.
func TestAServiceTellsTheBridgeAMemberLeftAndEverythingOfTheMembersGoes(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k, yaml: twoOAuthConnections})
		r.as.Revocation = true
		r.connect("bob")
		r.connectAs("acme", "bob", "crm")
		r.connect("alice")
		rt := r.as.RefreshTokenOf("bob")
		tok := r.tokenOf("bob")
		r.callAPI("POST", "/notes/authorization", "bob", "") // a pending authorization of bob's
		code, m := r.offboard("svc:lifecycle", offboardBody("acme", "bob", "user_deleted"))
		if code != 200 || m["grants_removed"] != float64(2) || m["revocations_failed"] != float64(0) {
			t.Fatalf("%d %v", code, m)
		}
		for _, key := range []string{"grants_removed", "revocations_failed", "reviewer_grants_marked"} {
			if _, ok := m[key]; !ok {
				t.Errorf("no %s in %v", key, m)
			}
		}
		if len(m) != 3 {
			t.Errorf("the answer is counts and nothing else: %v", m)
		}
		if !r.as.Revoked(rt) || !r.as.Revoked(tok) {
			t.Fatal("bob's tokens are still live at the third party")
		}
		revs := r.as.Requests("/revoke")
		if len(revs) < 2 || revs[0].Form.Get("token_type_hint") != "refresh_token" {
			t.Fatalf("the refresh token is revoked first: %+v", revs)
		}
		if gs, _ := r.store.ForMember(context.Background(), "acme", "bob"); len(gs) != 0 {
			t.Fatalf("%d grants are left", len(gs))
		}
		if m, ok := r.store.(*grants.Memory); ok && m.States() != 0 {
			t.Fatal("bob's pending authorization is left")
		}
		if _, err := r.store.Get(context.Background(), grants.Key{Tenant: "acme", Member: "alice", Connection: "notes"}); err != nil {
			t.Fatal("alice's grant went with bob's")
		}
		// the call of a member who is gone, and idempotence
		w, mm := r.call("notes", "acme", "bob", "whoami")
		if res := result(t, w, mm); !r.authRequired(res) {
			t.Fatalf("%s", w.Body)
		}
		code, m = r.offboard("svc:lifecycle", offboardBody("acme", "bob", "user_deleted"))
		if code != 200 || m["grants_removed"] != float64(0) {
			t.Fatalf("a second call: %d %v", code, m)
		}
		if code, m = r.offboard("svc:lifecycle", offboardBody("acme", "never-had-one", "other")); code != 200 || m["grants_removed"] != float64(0) {
			t.Fatalf("a member with no grants: %d %v", code, m)
		}
		r.noSecretsAnywhere(tok, rt)
	})
}

func TestTheRouteIsForServicesOnTheAllowListOnlyAndDisabledWithoutOne(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.connect("bob")
	body := offboardBody("acme", "bob", "user_deleted")
	for name, c := range map[string]struct {
		bearer string
		want   int
	}{"no token": {"", 401}, "not a token": {"junk", 401}, "a member's token": {"m:acme:bob", 403}, "the reviewer's token": {"r:acme:ops", 403}, "a client that is not on the list": {"svc:workspace", 403}} {
		if code, _ := r.offboard(c.bearer, body); code != c.want {
			t.Errorf("%s: %d", name, code)
		}
	}
	if _, err := r.store.Get(context.Background(), bobKey); err != nil {
		t.Fatal("a refused call removed the grant")
	}
	// a service of the list, and each of the reasons; anything else, and anything unknown in the body, is refused
	for _, reason := range []string{"user_deleted", "user_disabled", "tenant_changed", "operator", "other"} {
		if code, _ := r.offboard("svc:lifecycle2", offboardBody("acme", "nobody", reason)); code != 200 {
			t.Errorf("%s: %d", reason, code)
		}
	}
	for name, b := range map[string]string{"another reason": offboardBody("acme", "bob", "fired"), "no reason": `{"tenant":"acme","member":"bob"}`, "no tenant": offboardBody("", "bob", "other"),
		"no member": offboardBody("acme", "", "other"), "an extra field": `{"tenant":"acme","member":"bob","reason":"other","all":true}`, "not JSON": `x`} {
		if code, _ := r.offboard("svc:lifecycle", b); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	// without an allow-list the route does not exist
	req := httptest.NewRequest("POST", "/internal/v1/members/offboard", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer svc:lifecycle")
	w := httptest.NewRecorder()
	apiWithoutOffboarding(r).ServeHTTP(w, req)
	if w.Code != 404 && w.Code != 405 {
		t.Fatalf("%d", w.Code)
	}
}

func TestOffboardingIsAuditedWithTheReasonAndTheCallerAndCountedAndAFailedRevocationDoesNotKeepTheGrant(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.as.Revocation = true
	r.connect("bob")
	r.as.RevokeStatus = 503
	code, m := r.offboard("svc:lifecycle2", offboardBody("acme", "bob", "user_disabled"))
	if code != 200 || m["grants_removed"] != float64(1) || m["revocations_failed"] != float64(2) {
		t.Fatalf("%d %v", code, m)
	}
	if _, err := r.store.Get(context.Background(), bobKey); !errors.Is(err, grants.ErrNotFound) {
		t.Fatal("a failed revocation kept the grant")
	}
	var line map[string]any
	for _, l := range strings.Split(strings.TrimSpace(r.log.String()), "\n") {
		var x map[string]any
		if json.Unmarshal([]byte(l), &x) == nil && x["event"] == "offboard" {
			line = x
		}
	}
	if line == nil || line["reason"] != "user_disabled" || line["caller"] != "lifecycle2" || line["source"] != "route" || line["tenant"] != "acme" ||
		line["grants"] != float64(1) || line["revocationsFailed"] != float64(2) {
		t.Fatalf("%v", line)
	}
	if h, _ := line["member"].(string); len(h) != 8 || strings.Contains(r.log.String(), "\"bob\"") {
		t.Fatalf("the member is not a hash: %v", line["member"])
	}
	mt := r.metricsText()
	for _, want := range []string{`idp_bridge_offboard_total{reason="user_disabled",source="route"} 1`, `idp_bridge_offboard_grants_removed_total{reason="user_disabled"} 1`, `idp_bridge_offboard_revocation_failed_total{reason="user_disabled"} 2`} {
		if !strings.Contains(mt, want) {
			t.Errorf("no %q in\n%s", want, mt)
		}
	}
}

// ADR-0001 D40: the member who authorized a reviewer account left. The account is kept (removing it would make the service unusable for
// everyone) and marked, and an alert is raised; it is not revoked.
func TestWhenTheAuthorizerOfAReviewerAccountLeavesTheAccountIsKeptMarkedAndNotRevoked(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		r.as.Revocation = true
		r.authorizeReviewer("ops")
		r.authorizeReviewer("ops2")
		rtok := r.reviewerToken() // the second one's: one reviewer grant per connection
		r.connectAs("acme", "ops", "notes")
		code, m := r.offboard("svc:lifecycle", offboardBody("acme", "ops", "user_deleted"))
		if code != 200 || m["grants_removed"] != float64(1) || m["reviewer_grants_marked"] != float64(0) {
			t.Fatalf("ops authorized nothing now: %d %v", code, m)
		}
		// ops2 is the authorizer of the grant that exists
		revBefore := len(r.as.Requests("/revoke"))
		code, m = r.offboard("svc:lifecycle", offboardBody("acme", "ops2", "user_deleted"))
		if code != 200 || m["grants_removed"] != float64(0) || m["reviewer_grants_marked"] != float64(1) {
			t.Fatalf("%d %v", code, m)
		}
		g, err := r.store.Get(context.Background(), reviewerGrantKey)
		if err != nil || !g.AuthorizerLeft {
			t.Fatalf("%+v %v", g, err)
		}
		if r.as.Revoked(rtok) || len(r.as.Requests("/revoke")) != revBefore {
			t.Fatalf("the reviewer's tokens were revoked: %d new revocations", len(r.as.Requests("/revoke"))-revBefore)
		}
		// it still works
		if w, mm := r.list("notes"); len(result(t, w, mm)["tools"].([]any)) == 0 {
			t.Fatalf("%s", w.Body)
		}
		// the list says so, to operators
		_, rm := r.callAPIReviewer("GET", "", "ops3", "")
		var rv map[string]any
		for _, c := range rm["connections"].([]any) {
			if e := c.(map[string]any); e["id"] == "notes" {
				rv = e["reviewer"].(map[string]any)
			}
		}
		if rv["status"] != "connected" || rv["reason"] != "authorizer_left" || rv["scope"] != "list" {
			t.Fatalf("%v", rv)
		}
		if !strings.Contains(r.log.String(), "re-authorize it") || !strings.Contains(r.metricsText(), "idp_bridge_reviewer_authorizer_left_total 1") {
			t.Fatal("no alert")
		}
		// a member's list does not show it, and authorizing the account again clears the mark
		if _, mm := r.callAPI("GET", "", "ops3", ""); strings.Contains(asJSON(mm), "authorizer_left") {
			t.Fatal("a member sees it")
		}
		r.authorizeReviewer("ops3")
		if g, _ = r.store.Get(context.Background(), reviewerGrantKey); g.AuthorizerLeft || g.AuthorizedBy != "acme/ops3" {
			t.Fatalf("%+v", g)
		}
		// the departure of someone who authorized nothing, or of the member who left again, changes nothing
		if _, m = r.offboard("svc:lifecycle", offboardBody("acme", "ops2", "user_deleted")); m["reviewer_grants_marked"] != float64(0) {
			t.Fatalf("%v", m)
		}
	})
}

// Re-enabling never restores: the grants are gone and the member connects again.
func TestAMemberWhoComesBackConnectsAgainAndNothingIsRestored(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.connect("bob")
	r.offboard("svc:lifecycle", offboardBody("acme", "bob", "user_disabled"))
	_, list := r.callAPI("GET", "", "bob", "")
	if e := list["connections"].([]any)[0].(map[string]any); e["status"] != "not_connected" {
		t.Fatalf("%v", e)
	}
	w, m := r.call("notes", "acme", "bob", "whoami")
	if !r.authRequired(result(t, w, m)) {
		t.Fatalf("%s", w.Body)
	}
	if c, _ := r.connect("bob"); c != 200 {
		t.Fatal(c)
	}
	if tok, err := r.svc.Token(context.Background(), auth.Subject{Tenant: "acme", Member: "bob"}, "notes"); err != nil || tok == "" {
		t.Fatalf("%v", err)
	}
}

func TestTheOperatorsRevokeCommandIsTheSamePathWithReasonOperator(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.as.Revocation = true
	r.connect("bob")
	rt := r.as.RefreshTokenOf("bob")
	if n, err := r.svc.RevokeMember(context.Background(), "acme", "bob", ""); err != nil || n != 1 || !r.as.Revoked(rt) {
		t.Fatalf("%d %v", n, err)
	}
	if !strings.Contains(r.metricsText(), `idp_bridge_offboard_total{reason="operator",source="command"} 1`) {
		t.Fatalf("%s", r.metricsText())
	}
	// limited to one connection it is not a departure: the pending authorizations stay
	r.connect("bob")
	r.callAPI("POST", "/notes/authorization", "bob", "")
	if _, err := r.svc.RevokeMember(context.Background(), "acme", "bob", "notes"); err != nil {
		t.Fatal(err)
	}
	if m := r.store.(*grants.Memory); m.States() == 0 {
		t.Fatal("a one-connection revoke removed the pending authorizations")
	}
}

// apiWithoutOffboarding is the API of a bridge with no allow-list: the same handler, without the route.
func apiWithoutOffboarding(r *orig) http.Handler { return api.New(testAuthenticator{}, r.svc) }

// The reconciliation finds an operator who authorized a reviewer account and holds no member grant (ADR-0001 D40).
func TestTheReconciliationMarksAReviewerAccountWhoseAuthorizerHoldsNoGrantsAndHasLeft(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		r.authorizeReviewer("ops") // ops holds no member grant
		r.connect("bob")
		rc := &reconcile.Reconciler{Store: r.store, Dir: opsGone{}, Off: r.svc, Log: slog.New(slog.NewJSONHandler(r.log, nil)), Counters: r.met}
		rep, err := rc.Round(context.Background(), false)
		if err != nil || rep.Members != 2 || rep.Leaving != 1 || rep.Offboarded != 1 {
			t.Fatalf("%+v %v", rep, err)
		}
		g, err := r.store.Get(context.Background(), reviewerGrantKey)
		if err != nil || !g.AuthorizerLeft {
			t.Fatalf("%+v %v", g, err)
		}
		if _, err := r.store.Get(context.Background(), bobKey); err != nil {
			t.Fatal("bob, who is present, was offboarded")
		}
		if !strings.Contains(r.log.String(), "re-authorize it") || !strings.Contains(r.log.String(), `"event":"authorizer_left"`) {
			t.Fatal("no alert or audit")
		}
		if w, m := r.list("notes"); len(result(t, w, m)["tools"].([]any)) == 0 {
			t.Fatal("the account was revoked")
		}
	})
}

type opsGone struct{}

func (opsGone) Lookup(_ context.Context, tenant, member string) (directory.Status, error) {
	if member == "ops" {
		return directory.Deleted, nil
	}
	return directory.Present, nil
}
