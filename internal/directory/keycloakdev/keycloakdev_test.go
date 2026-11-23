package keycloakdev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"idp-mcp-bridge/internal/directory"
)

// kc is a Keycloak as far as the adapter sees it.
type kc struct {
	*httptest.Server
	tokens, users atomic.Int32
	user          func(id string) (int, string)
	tokenStatus   int
	revoke        atomic.Bool // the next user request answers 401 once
	lastAuth      atomic.Value
}

func newKC(t *testing.T) *kc {
	k := &kc{tokenStatus: 200}
	k.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/realms/idp/protocol/openid-connect/token":
			k.tokens.Add(1)
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "bridge-directory" || r.Form.Get("client_secret") != "s3cret" {
				w.WriteHeader(401)
				return
			}
			if k.tokenStatus != 200 {
				w.WriteHeader(k.tokenStatus)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"tok-` + string(rune('a'+int(k.tokens.Load()))) + `","expires_in":300}`))
		case strings.HasPrefix(r.URL.Path, "/admin/realms/idp/users/"):
			k.users.Add(1)
			k.lastAuth.Store(r.Header.Get("Authorization"))
			if k.revoke.CompareAndSwap(true, false) {
				w.WriteHeader(401)
				return
			}
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer tok-") {
				w.WriteHeader(401)
				return
			}
			code, body := k.user(strings.TrimPrefix(r.URL.Path, "/admin/realms/idp/users/"))
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(k.Close)
	return k
}

func (k *kc) dir(t *testing.T) *Directory {
	d, err := New(Config{URL: k.URL, Realm: "idp", ClientID: "bridge-directory", ClientSecret: "s3cret", HTTP: k.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func user(id string, enabled bool, tenant string) string {
	b, _ := json.Marshal(map[string]any{"id": id, "enabled": enabled, "attributes": map[string][]string{"tenant_id": {tenant}}})
	return string(b)
}

func TestTheAdapterGivesOnlyClearAnswers(t *testing.T) {
	k := newKC(t)
	d := k.dir(t)
	cases := []struct {
		name string
		resp func(id string) (int, string)
		want directory.Status
	}{
		{"present", func(id string) (int, string) { return 200, user(id, true, "acme") }, directory.Present},
		{"disabled", func(id string) (int, string) { return 200, user(id, false, "acme") }, directory.Disabled},
		{"deleted", func(id string) (int, string) { return 404, `{"error":"User not found"}` }, directory.Deleted},
		{"moved", func(id string) (int, string) { return 200, user(id, true, "other") }, directory.Moved},
		{"disabled wins over moved", func(id string) (int, string) { return 200, user(id, false, "other") }, directory.Disabled},
		{"a 404 for the realm is not a deleted user", func(id string) (int, string) { return 404, `{"error":"Realm not found."}` }, directory.Unknown},
		{"a 404 with a body that says nothing", func(id string) (int, string) { return 404, `` }, directory.Unknown},
		{"no tenant attribute: nothing to compare", func(id string) (int, string) { return 200, `{"id":"` + id + `","enabled":true}` }, directory.Unknown},
		{"another user's id", func(id string) (int, string) { return 200, user("someone-else", true, "acme") }, directory.Unknown},
		{"no enabled field", func(id string) (int, string) { return 200, `{"id":"` + id + `","attributes":{"tenant_id":["acme"]}}` }, directory.Unknown},
		{"not JSON", func(id string) (int, string) { return 200, `<html>` }, directory.Unknown},
		{"500", func(id string) (int, string) { return 500, `` }, directory.Unknown},
		{"403 (no permission)", func(id string) (int, string) { return 403, `{"error":"forbidden"}` }, directory.Unknown},
		{"429", func(id string) (int, string) { return 429, `` }, directory.Unknown},
	}
	for _, c := range cases {
		k.user = c.resp
		got, err := d.Lookup(context.Background(), "acme", "u-1")
		if got != c.want || (c.want == directory.Unknown) != (err != nil) {
			t.Errorf("%s: %v %v", c.name, got, err)
		}
	}
}

func TestTheTenantAttributeIsConfigurableAndATokenIsKeptUntilItExpiresAndRenewedOnce(t *testing.T) {
	k := newKC(t)
	k.user = func(id string) (int, string) {
		b, _ := json.Marshal(map[string]any{"id": id, "enabled": true, "attributes": map[string][]string{"org": {"acme"}}})
		return 200, string(b)
	}
	d, _ := New(Config{URL: k.URL, Realm: "idp", ClientID: "bridge-directory", ClientSecret: "s3cret", HTTP: k.Client(), TenantAttribute: "org"})
	for i := 0; i < 3; i++ {
		if st, err := d.Lookup(context.Background(), "acme", "u-1"); st != directory.Present || err != nil {
			t.Fatalf("%v %v", st, err)
		}
	}
	if k.tokens.Load() != 1 {
		t.Fatalf("%d tokens for three lookups", k.tokens.Load())
	}
	// a token that Keycloak no longer accepts: one new token, one retry
	k.revoke.Store(true)
	if st, err := d.Lookup(context.Background(), "acme", "u-1"); st != directory.Present || err != nil || k.tokens.Load() != 2 {
		t.Fatalf("%v %v %d", st, err, k.tokens.Load())
	}
	// and a token that expired by the clock
	now := time.Now()
	d.c.Now = func() time.Time { return now.Add(10 * time.Minute) }
	d.Lookup(context.Background(), "acme", "u-1")
	if k.tokens.Load() != 3 {
		t.Fatalf("%d", k.tokens.Load())
	}
}

func TestWhenKeycloakCannotBeAskedTheAnswerIsUnknownAndNothingIsAsked(t *testing.T) {
	k := newKC(t)
	k.user = func(id string) (int, string) { return 404, `{"error":"User not found"}` }
	k.tokenStatus = 503
	d := k.dir(t)
	if st, err := d.Lookup(context.Background(), "acme", "u-1"); st != directory.Unknown || err == nil || k.users.Load() != 0 {
		t.Fatalf("the token endpoint is down: %v %v", st, err)
	}
	bad, _ := New(Config{URL: k.URL, Realm: "idp", ClientID: "bridge-directory", ClientSecret: "wrong", HTTP: k.Client()})
	k.tokenStatus = 200
	if st, _ := bad.Lookup(context.Background(), "acme", "u-1"); st != directory.Unknown || k.users.Load() != 0 {
		t.Fatalf("a wrong secret: %v", st)
	}
	k.Close()
	if st, err := d.Lookup(context.Background(), "acme", "u-1"); st != directory.Unknown || err == nil {
		t.Fatalf("unreachable: %v %v", st, err)
	}
	// a member id that could be a path is not asked about
	k2 := newKC(t)
	k2.user = func(id string) (int, string) { return 404, `{"error":"User not found"}` }
	d2 := k2.dir(t)
	for _, id := range []string{"", "a/b", "../x", "a\x00b"} {
		if st, _ := d2.Lookup(context.Background(), "acme", id); st != directory.Unknown {
			t.Errorf("%q: %v", id, st)
		}
	}
	if k2.users.Load() != 0 {
		t.Fatal("a request was made for an id that is not one")
	}
	if _, err := New(Config{URL: "x"}); err == nil {
		t.Fatal("incomplete configuration")
	}
}
