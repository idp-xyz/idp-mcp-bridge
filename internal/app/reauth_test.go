package app

import (
	"context"
	"strings"
	"testing"
)

// ADR-0001 D35: when a member (or the reviewer account) authorizes again, the grant is replaced and the tokens it superseded are
// revoked at the server, refresh token first, best effort, after the new grant is stored.
func TestAuthorizingAgainRevokesTheSupersededTokensAndTheNewGrantWorks(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		r.as.Revocation = true
		r.connect("bob")
		oldTok, oldRT := r.tokenOf("bob"), r.as.RefreshTokenOf("bob")
		if len(r.as.Requests("/revoke")) != 0 {
			t.Fatal("the first authorization revoked something")
		}
		if code, m := r.connect("bob"); code != 200 {
			t.Fatalf("%d %v", code, m)
		}
		if !r.as.Revoked(oldTok) || !r.as.Revoked(oldRT) {
			t.Fatal("the superseded tokens are still live at the server")
		}
		revs := r.as.Requests("/revoke")
		if len(revs) != 2 || revs[0].Form.Get("token_type_hint") != "refresh_token" || revs[1].Form.Get("token_type_hint") != "access_token" {
			t.Fatalf("%+v", revs)
		}
		newTok := r.tokenOf("bob")
		if newTok == oldTok || r.as.Revoked(newTok) || r.as.Revoked(r.as.RefreshTokenOf("bob")) {
			t.Fatal("the new grant's tokens were revoked, or are the old ones")
		}
		w, m := r.call("notes", "acme", "bob", "whoami")
		if text(result(t, w, m)) != "token of bob" {
			t.Fatalf("%s", w.Body)
		}
		r.noSecretsAnywhere(oldTok, oldRT)
	})
}

func TestAuthorizingAgainAfterAStepUpRevokesTheSupersededTokens(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.as.Revocation = true
	r.connect("bob")
	oldTok, oldRT := r.tokenOf("bob"), r.as.RefreshTokenOf("bob")
	r.call("notes", "acme", "bob", "write") // insufficient_scope: the grant stays, unusable
	if r.as.Revoked(oldTok) {
		t.Fatal("the grant's tokens were revoked by the step-up itself")
	}
	r.connect("bob")
	if !r.as.Revoked(oldTok) || !r.as.Revoked(oldRT) {
		t.Fatal("the tokens of the grant that was too small are still live")
	}
	w, m := r.call("notes", "acme", "bob", "write")
	if text(result(t, w, m)) != "written by bob" {
		t.Fatalf("%s", w.Body)
	}
}

func TestWithoutARevocationEndpointAuthorizingAgainJustReplacesTheGrant(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.connect("bob")
	if code, _ := r.connect("bob"); code != 200 {
		t.Fatal(code)
	}
	if len(r.as.Requests("/revoke")) != 0 {
		t.Fatal("a revocation was attempted at a server that has no endpoint")
	}
	w, m := r.call("notes", "acme", "bob", "whoami")
	if text(result(t, w, m)) != "token of bob" {
		t.Fatalf("%s", w.Body)
	}
}

func TestAFailingRevocationNeverUndoesTheNewGrantAndOnlyItsCodeIsLogged(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.as.Revocation = true
	r.connect("bob")
	oldTok, oldRT := r.tokenOf("bob"), r.as.RefreshTokenOf("bob")
	r.as.RevokeStatus = 503
	if code, m := r.connect("bob"); code != 200 || m["status"] != "connected" {
		t.Fatalf("%d %v", code, m)
	}
	g, err := r.store.Get(context.Background(), bobKey)
	if err != nil || g.ReauthReason != "" {
		t.Fatalf("%+v %v", g, err)
	}
	if tok := r.tokenOf("bob"); tok == oldTok {
		t.Fatal("the old grant is still the grant")
	}
	if w, m := r.call("notes", "acme", "bob", "whoami"); text(result(t, w, m)) != "token of bob" {
		t.Fatalf("%s", w.Body)
	}
	if !strings.Contains(r.log.String(), "revocation failed") {
		t.Fatal("the failure was not logged")
	}
	r.noSecretsAnywhere(oldTok, oldRT)
}

// Tokens of another authorization server are not shown to this one.
func TestTokensOfAnotherIssuerAreNotSentToTheCurrentServerForRevocation(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.as.Revocation = true
	r.connect("bob")
	g, _ := r.store.Get(context.Background(), bobKey)
	g.Issuer = "https://old.example.com"
	_ = r.store.Put(context.Background(), g)
	if code, _ := r.connect("bob"); code != 200 {
		t.Fatal(code)
	}
	if len(r.as.Requests("/revoke")) != 0 {
		t.Fatal("a token of another issuer was sent to this server")
	}
}

func TestAuthorizingTheReviewerAccountAgainRevokesTheSupersededReviewerTokens(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		r.as.Revocation = true
		r.authorizeReviewer("ops")
		oldTok := r.reviewerToken()
		oldRT := r.as.RefreshTokenOf("reviewer-account")
		if oldRT == "" {
			t.Fatal("no refresh token")
		}
		if code, m := r.authorizeReviewer("ops"); code != 200 {
			t.Fatalf("%d %v", code, m)
		}
		if !r.as.Revoked(oldTok) || !r.as.Revoked(oldRT) {
			t.Fatal("the superseded reviewer tokens are live")
		}
		newTok := r.reviewerToken()
		if newTok == oldTok || r.as.Revoked(newTok) {
			t.Fatal("the new reviewer token is the old one or was revoked")
		}
		if w, m := r.list("notes"); len(result(t, w, m)["tools"].([]any)) == 0 {
			t.Fatalf("%s", w.Body)
		}
		// a member's own authorization of the same person is not touched by it
		r.connectAs("acme", "ops", "notes")
		mtok := r.tokenOf("ops")
		r.authorizeReviewer("ops")
		if r.as.Revoked(mtok) {
			t.Fatal("authorizing the reviewer account revoked the operator's own member tokens")
		}
	})
}
