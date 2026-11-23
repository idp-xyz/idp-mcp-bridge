package app

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"idp-mcp-bridge/internal/grants"
)

// ADR-0001 D36: an authorization server that answers an error with HTTP 200 and an `error` in the body (GitHub's token endpoint).
func TestAnErrorAnsweredWithHTTP200IsAnErrorAndAGitHubDeadRefreshTokenDeletesTheGrant(t *testing.T) {
	forStores(t, func(t *testing.T, k storeKind) {
		r := newORig(t, orgOpts{store: k})
		r.as.ExpiresIn = 30
		r.connect("bob")
		r.as.RefreshError200 = "bad_refresh_token"
		w, m := r.call("notes", "acme", "bob", "whoami")
		if res := result(t, w, m); !r.authRequired(res) {
			t.Fatalf("a dead refresh token is not 'authorize again': %s", w.Body)
		}
		if _, err := r.store.Get(context.Background(), bobKey); !errors.Is(err, grants.ErrNotFound) {
			t.Fatalf("the grant is still there: %v", err)
		}
		// and the member can connect again
		r.as.RefreshError200 = ""
		r.as.ExpiresIn = 3600
		if c, _ := r.connect("bob"); c != 200 {
			t.Fatal(c)
		}
		r.noSecretsAnywhere()
	})
}

func TestAGitHubBadCodeIsInvalidGrantAndTheOtherGitHubErrorsAreErrorsOfTheTokenEndpoint(t *testing.T) {
	for given, want := range map[string]string{"bad_verification_code": "invalid_grant", "incorrect_client_credentials": "token_endpoint_error",
		"redirect_uri_mismatch": "token_endpoint_error", "unverified_user_email": "token_endpoint_error", "something_new": "token_endpoint_error"} {
		r := newORig(t, orgOpts{})
		r.as.CodeError200 = given
		code, m := r.connect("bob")
		if code != 502 || m["error"] != "authorization_failed" || m["reason"] != want {
			t.Errorf("%s: %d %v", given, code, m)
		}
		if _, err := r.store.Get(context.Background(), bobKey); err == nil {
			t.Errorf("%s: a grant was made", given)
		}
		for _, s := range r.seen {
			if strings.Contains(s, "secret detail") {
				t.Errorf("%s: the server's words reached the member", given)
			}
		}
	}
}

// Only GitHub's two codes mean "dead grant": any other error in a 200 does not delete a grant.
func TestOnlyTheTwoListedCodesDeleteAGrantWhenARefreshIsRefusedWith200(t *testing.T) {
	r := newORig(t, orgOpts{})
	r.as.ExpiresIn = 30
	r.connect("bob")
	r.as.RefreshError200 = "incorrect_client_credentials"
	w, m := r.call("notes", "acme", "bob", "whoami")
	if res := result(t, w, m); r.authRequired(res) || res["isError"] != true {
		t.Fatalf("%s", w.Body)
	}
	if _, err := r.store.Get(context.Background(), bobKey); err != nil {
		t.Fatal("a configuration error of the token endpoint deleted the grant")
	}
}

// ADR-0001 D37: the authorization request asks for exactly the connection's scopes. None configured: no scope parameter at all, and
// no offline_access, whatever the resource and the server list. The resource's list only on the explicit opt-in.
func TestTheAuthorizationAskedForIsTheConfiguredScopesAndTheResourcesListOnlyOnTheOptIn(t *testing.T) {
	secret := t.TempDir() + "/secret"
	if err := writeFile(secret, "s3cret\n"); err != nil {
		t.Fatal(err)
	}
	yaml := func(extra string) func(r *orig) string {
		return func(r *orig) string {
			return `
connections:
  - id: notes
    title: Notes
    endpoint: ` + r.tp.URL() + `
    authorization:
      mode: oauth
      issuer: ` + r.as.Issuer() + `
      client: {mode: preregistered, id: Iv1.abc, secretFile: ` + secret + `}
` + extra
		}
	}
	for _, c := range []struct {
		name      string
		extra     string
		offline   bool
		wantScope string
		prompt    bool
	}{
		{"nothing configured, the resource lists scopes, the server lists offline_access (GitHub)", "", true, "", false},
		{"nothing configured, nothing offered by the server", "", false, "", false},
		{"the opt-in: the resource's list, and offline_access", "      scopesFromResource: true\n", true, "repo read:org offline_access", true},
		{"the opt-in, a server without offline_access", "      scopesFromResource: true\n", false, "repo read:org", false},
		{"configured scopes win over the opt-in", "      scopes: [read]\n      scopesFromResource: true\n", true, "read offline_access", true},
		{"configured scopes, offline_access listed", "      scopes: [read]\n", true, "read offline_access", true},
		{"configured scopes, not listed", "      scopes: [read]\n", false, "read", false},
	} {
		r := newORig(t, orgOpts{yaml: yaml(c.extra), mod: func(r *orig) {
			r.tp.PRM["scopes_supported"] = []string{"repo", "read:org"}
			if c.offline {
				r.as.ScopesSupported = []string{"offline_access"}
			}
			r.as.Preregister("Iv1.abc", "s3cret")
		}})
		_, m := r.callAPI("POST", "/notes/authorization", "bob", "")
		q := query(m["url"].(string))
		if q.Get("scope") != c.wantScope || (q.Get("prompt") == "consent") != c.prompt || q.Get("client_id") != "Iv1.abc" || q.Get("resource") != r.tp.URL() {
			t.Errorf("%s: %v", c.name, q)
		}
		if _, has := q["scope"]; has != (c.wantScope != "") {
			t.Errorf("%s: scope present %v", c.name, has)
		}
		// the reviewer account asks for the same, or its own list: never the resource's unless opted in
		_, rm := r.callAPIReviewer("POST", "/notes/reviewer/authorization", "ops", "")
		if rq := query(rm["url"].(string)); rq.Get("scope") != c.wantScope {
			t.Errorf("%s (reviewer): %q", c.name, rq.Get("scope"))
		}
	}
}

// A challenge from the third party can still widen the next authorization, and the names added are logged.
func TestAStepUpStillUnionsTheChallengedScopeWithNoScopesConfiguredAndLogsTheNamesAdded(t *testing.T) {
	r := newORig(t, orgOpts{yaml: func(r *orig) string {
		return strings.Replace(defaultYAML(r), "      scopes: [read]\n      reviewerScopes: [list]\n", "", 1)
	}})
	if c, m := r.connect("bob"); c != 200 {
		t.Fatalf("%d %v", c, m)
	}
	if sc := r.as.Requests("/authorize")[0].Form.Get("scope"); sc != "" {
		t.Fatalf("scope %q was asked for with none configured", sc)
	}
	w, m := r.call("notes", "acme", "bob", "write")
	if res := result(t, w, m); !r.authRequired(res) {
		t.Fatalf("%s", w.Body)
	}
	if !strings.Contains(r.log.String(), `"added":"write"`) {
		t.Fatalf("the widening is not logged: %s", r.log.String())
	}
	if c, _ := r.connect("bob"); c != 200 {
		t.Fatal(c)
	}
	reqs := r.as.Requests("/authorize")
	if sc := reqs[len(reqs)-1].Form.Get("scope"); sc != "write" {
		t.Fatalf("asked for %q after the step-up", sc)
	}
}

func writeFile(p, c string) error { return os.WriteFile(p, []byte(c), 0o600) }
