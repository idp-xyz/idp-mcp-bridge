package app

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"idp-mcp-bridge/internal/config"
)

// githubYAML is a connection at an authorization server that has no revocation endpoint, with GitHub's revocation API.
func githubRig(t *testing.T, mod func(r *orig)) *orig { return githubRigOn(t, storeKinds()[0], mod) }

func githubRigOn(t *testing.T, k storeKind, mod func(r *orig)) *orig {
	t.Helper()
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return newORig(t, orgOpts{store: k, yaml: func(r *orig) string {
		return `
connections:
  - id: notes
    title: Notes
    endpoint: ` + r.tp.URL() + `
    authorization:
      mode: oauth
      issuer: ` + r.as.Issuer() + `
      client: {mode: preregistered, id: Iv1.abc, secretFile: ` + secret + `}
      revocation: github
`
	}, mod: func(r *orig) {
		r.as.Preregister("Iv1.abc", "s3cret")
		if mod != nil {
			mod(r)
		}
	}})
}

// ADR-0001 D42: GitHub's own revocation API: the whole grant, with the application's id and secret and the member's access token.
func TestDisconnectingFromGitHubDeletesTheMembersGrantAtGitHubWithTheApplicationsCredentials(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := githubRigOn(t, k, func(r *orig) { r.as.Revocation = false })
		r.connect("bob")
		tok := r.tokenOf("bob")
		if code, _ := r.callAPI("DELETE", "/notes/grant", "bob", ""); code != 204 {
			t.Fatal(code)
		}
		reqs := r.gh.Requests()
		if len(reqs) != 1 || reqs[0].Method != "DELETE" || reqs[0].Path != "/applications/Iv1.abc/grant" || reqs[0].AccessToken != tok {
			t.Fatalf("%+v", reqs)
		}
		q := reqs[0]
		if q.User != "Iv1.abc" || q.Pass != "s3cret" || q.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("Iv1.abc:s3cret")) ||
			q.Header.Get("Accept") != "application/vnd.github+json" || q.Header.Get("X-GitHub-Api-Version") != "2022-11-28" || q.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("%v", q.Header)
		}
		if len(r.as.Requests("/revoke")) != 0 {
			t.Fatal("RFC 7009 was used for a connection that says github")
		}
		if _, err := r.store.Get(context.Background(), bobKey); err == nil {
			t.Fatal("the grant is still stored")
		}
		r.noSecretsAnywhere(tok, "s3cret")
	})
}

func TestAnExpiredAccessTokenIsRefreshedFirstIfThereIsARefreshTokenAndOtherwiseThePresentedOneIsTheStaleOne(t *testing.T) {
	r := githubRig(t, nil)
	r.as.ExpiresIn = 3600
	r.connect("bob")
	stale := r.tokenOf("bob")
	r.as.ExpireAll()
	g, _ := r.store.Get(context.Background(), bobKey)
	g.AccessExpires = time.Now().Add(-time.Minute)
	_ = r.store.Put(context.Background(), g)
	if code, _ := r.callAPI("DELETE", "/notes/grant", "bob", ""); code != 204 {
		t.Fatal(code)
	}
	reqs := r.gh.Requests()
	if len(reqs) != 1 || reqs[0].AccessToken == stale || reqs[0].AccessToken == "" || r.as.Count("/token", "refresh_token") != 1 {
		t.Fatalf("%+v (%d refreshes)", reqs, r.as.Count("/token", "refresh_token"))
	}
	// no refresh token: the stale token is what there is to present
	r2 := githubRig(t, func(r *orig) { r.as.NoRefreshToken = true })
	r2.connect("bob")
	stale2 := r2.tokenOf("bob")
	g, _ = r2.store.Get(context.Background(), bobKey)
	g.AccessExpires = time.Now().Add(-time.Minute)
	_ = r2.store.Put(context.Background(), g)
	r2.callAPI("DELETE", "/notes/grant", "bob", "")
	if reqs := r2.gh.Requests(); len(reqs) != 1 || reqs[0].AccessToken != stale2 || r2.as.Count("/token", "refresh_token") != 0 {
		t.Fatalf("%+v", reqs)
	}
	// a token that is still good is not refreshed to be revoked
	r3 := githubRig(t, nil)
	r3.connect("bob")
	r3.callAPI("DELETE", "/notes/grant", "bob", "")
	if r3.as.Count("/token", "refresh_token") != 0 {
		t.Fatal("a refresh was made for a token that is good")
	}
}

func TestGitHubSaying404Or422MeansAlreadyGoneAndAnythingElseFallsBackToTheTokenEndpointAndThenFails(t *testing.T) {
	for _, code := range []int{404, 422} {
		r := githubRig(t, nil)
		r.gh.Status["grant"] = code
		r.connect("bob")
		c, m := r.offboard("svc:lifecycle", offboardBody("acme", "bob", "user_deleted"))
		if c != 200 || m["revocations_failed"] != float64(0) || len(r.gh.Requests()) != 1 {
			t.Fatalf("%d: %d %v %d requests", code, c, m, len(r.gh.Requests()))
		}
		if !strings.Contains(r.log.String(), "already gone") {
			t.Errorf("%d: not logged", code)
		}
	}
	// the grant endpoint fails, the token endpoint works: revoked
	r := githubRig(t, nil)
	r.gh.Status["grant"] = 500
	r.connect("bob")
	_, m := r.offboard("svc:lifecycle", offboardBody("acme", "bob", "other"))
	reqs := r.gh.Requests()
	if m["revocations_failed"] != float64(0) || len(reqs) != 2 || reqs[0].Path != "/applications/Iv1.abc/grant" || reqs[1].Path != "/applications/Iv1.abc/token" || reqs[1].AccessToken != reqs[0].AccessToken {
		t.Fatalf("%v %+v", m, reqs)
	}
	// both fail: a failure, the grant deleted all the same, only codes logged
	r = githubRig(t, nil)
	r.gh.Status["grant"], r.gh.Status["token"] = 500, 403
	r.connect("bob")
	tok := r.tokenOf("bob")
	_, m = r.offboard("svc:lifecycle", offboardBody("acme", "bob", "other"))
	if m["revocations_failed"] != float64(1) || m["grants_removed"] != float64(1) {
		t.Fatalf("%v", m)
	}
	if _, err := r.store.Get(context.Background(), bobKey); err == nil {
		t.Fatal("a failed revocation kept the grant")
	}
	if !strings.Contains(r.log.String(), "revocation at GitHub failed") {
		t.Fatal("not logged")
	}
	r.noSecretsAnywhere(tok, "s3cret")
}

// The honest status: the member disconnected and GitHub's revocation could not be confirmed; the list says so until they connect again.
func TestAMemberWhoseRevocationCouldNotBeConfirmedIsToldSoInTheListUntilTheyConnectAgain(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := githubRigOn(t, k, nil)
		r.gh.Status["grant"], r.gh.Status["token"] = 500, 500
		r.connect("bob")
		r.callAPI("DELETE", "/notes/grant", "bob", "")
		entry := func() map[string]any {
			_, l := r.callAPI("GET", "", "bob", "")
			return l["connections"].([]any)[0].(map[string]any)
		}
		if e := entry(); e["status"] != "not_connected" || e["reason"] != "revocation_unconfirmed" {
			t.Fatalf("%v", e)
		}
		// a revocation that went through leaves no such mark
		r2 := githubRig(t, nil)
		r2.connect("bob")
		r2.callAPI("DELETE", "/notes/grant", "bob", "")
		if _, l := r2.callAPI("GET", "", "bob", ""); l["connections"].([]any)[0].(map[string]any)["reason"] != nil {
			t.Fatalf("%v", l)
		}
		r.gh.Status["grant"], r.gh.Status["token"] = 0, 0
		r.connect("bob")
		if e := entry(); e["status"] != "connected" || e["reason"] != nil {
			t.Fatalf("%v", e)
		}
		r.callAPI("DELETE", "/notes/grant", "bob", "")
		if e := entry(); e["reason"] != nil {
			t.Fatalf("the mark came back: %v", e)
		}
	})
}

// Authorizing again must not use the grant endpoint: the grant of the same user and application is the new authorization's too.
func TestAuthorizingAgainAtGitHubRevokesOnlyTheOldTokenAndNeverTheGrant(t *testing.T) {
	r := githubRig(t, nil)
	r.connect("bob")
	oldTok := r.tokenOf("bob")
	if c, _ := r.connect("bob"); c != 200 {
		t.Fatal(c)
	}
	reqs := r.gh.Requests()
	if len(reqs) != 1 || reqs[0].Path != "/applications/Iv1.abc/token" || reqs[0].AccessToken != oldTok {
		t.Fatalf("%+v", reqs)
	}
	for _, q := range reqs {
		if strings.HasSuffix(q.Path, "/grant") {
			t.Fatal("the whole grant was deleted: that revokes the new tokens too")
		}
	}
	if w, m := r.call("notes", "acme", "bob", "whoami"); text(result(t, w, m)) != "token of bob" {
		t.Fatalf("%s", w.Body)
	}
	// a failing GitHub never undoes the new grant
	r.gh.Status["token"] = 500
	if c, _ := r.connect("bob"); c != 200 {
		t.Fatal(c)
	}
	if _, err := r.store.Get(context.Background(), bobKey); err != nil {
		t.Fatal(err)
	}
}

func TestTheReviewerAccountAndTheOperatorsRevokeUseGitHubsAPIToo(t *testing.T) {
	r := githubRig(t, nil)
	r.authorizeReviewer("ops")
	if c, _ := r.callAPIReviewer("DELETE", "/notes/reviewer/grant", "ops", ""); c != 204 {
		t.Fatal(c)
	}
	if reqs := r.gh.Requests(); len(reqs) != 1 || reqs[0].Path != "/applications/Iv1.abc/grant" {
		t.Fatalf("%+v", reqs)
	}
	r.connect("carol")
	if n, err := r.svc.RevokeMember(context.Background(), "acme", "carol", ""); err != nil || n != 1 || len(r.gh.Requests()) != 2 {
		t.Fatalf("%d %v %d", n, err, len(r.gh.Requests()))
	}
}

func TestRevocationGitHubIsForPreregisteredClientsOnly(t *testing.T) {
	const pre = `connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: oauth, issuer: "https://github.com/login/oauth", client: {mode: preregistered, id: x, secretFile: /s}, revocation: github}}]`
	if cs, err := config.Parse([]byte(pre), config.Options{}); err != nil || cs[0].Authorization.Revocation != "github" {
		t.Fatalf("%v", err)
	}
	for name, y := range map[string]string{
		"a cimd client":     `connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: oauth, issuer: "https://as.example.com", client: {mode: cimd, document: "https://w.example.com/c.json"}, revocation: github}}]`,
		"no token needed":   `connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: none, revocation: github}}]`,
		"another mechanism": strings.Replace(pre, "revocation: github", "revocation: gitlab", 1),
	} {
		if _, err := config.Parse([]byte(y), config.Options{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
