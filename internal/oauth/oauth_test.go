package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"idp-mcp-bridge/internal/egress"
)

func TestParseChallengeReadsTheParametersOfTheBearerChallenge(t *testing.T) {
	cases := []struct {
		header string
		want   map[string]string
	}{
		{`Bearer error="insufficient_scope", scope="read write", resource_metadata="https://a.example.com/x"`, map[string]string{"error": "insufficient_scope", "scope": "read write", "resource_metadata": "https://a.example.com/x"}},
		{`bearer realm=example, error=invalid_token`, map[string]string{"realm": "example", "error": "invalid_token"}},
		{`Bearer scope="a \"quoted\" b,c"`, map[string]string{"scope": `a "quoted" b,c`}},
		{`Bearer error="insufficient_scope",scope="x"`, map[string]string{"error": "insufficient_scope", "scope": "x"}},
		{`Bearer error="a", error="b"`, map[string]string{"error": "a"}},
		{`Bearer`, map[string]string{}},
		{`Bearer resource_metadata="https://a.example.com/x", Basic realm="y"`, map[string]string{"resource_metadata": "https://a.example.com/x"}},
		{`Bearer scope="cut off`, map[string]string{}},
	}
	for _, c := range cases {
		got := ParseChallenge(c.header)
		if len(got) != len(c.want) {
			t.Errorf("%s: %v", c.header, got)
			continue
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%s: %s = %q", c.header, k, got[k])
			}
		}
	}
	for _, h := range []string{"", "Basic realm=x", "Bearerx error=y", "Negotiate"} {
		if ParseChallenge(h) != nil {
			t.Errorf("%q is not a Bearer challenge", h)
		}
	}
}

func TestTheFetcherFollowsOnlySameOriginRedirectsThatKeepTheMethodAndBoundsTheBody(t *testing.T) {
	var hits []string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/a":
			http.Redirect(w, r, "/b", http.StatusTemporaryRedirect)
		case "/b":
			_, _ = w.Write([]byte("ok " + r.Method))
		case "/303":
			http.Redirect(w, r, "/b", http.StatusSeeOther)
		case "/302":
			http.Redirect(w, r, "/b", http.StatusFound)
		case "/away":
			http.Redirect(w, r, "https://evil.example.com/x", http.StatusTemporaryRedirect)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusTemporaryRedirect)
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("x", 5000)))
		}
	}))
	defer srv.Close()
	origin := strings.TrimPrefix(srv.URL, "http://")
	f := &Fetcher{HTTP: egress.NewClient(egress.Options{TestOrigins: map[string]bool{origin: true}}), TestOrigins: map[string]bool{origin: true}, MaxBody: 1000}
	do := func(method, path string) (*Response, error) {
		return f.Do(context.Background(), method, srv.URL+path, nil, []byte("body"))
	}
	if r, err := do("POST", "/a"); err != nil || string(r.Body) != "ok POST" {
		t.Fatalf("a 307 keeps the method: %v %v", r, err)
	}
	if r, err := do("GET", "/302"); err != nil || string(r.Body) != "ok GET" {
		t.Fatalf("a GET after 302: %v %v", r, err)
	}
	for name, c := range map[string][2]string{"a POST after 303": {"POST", "/303"}, "a POST after 302": {"POST", "/302"}, "another origin": {"GET", "/away"}, "a loop": {"GET", "/loop"}} {
		if _, err := do(c[0], c[1]); err == nil || err.(*Error).Code != CodeRedirectRefused {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := do("GET", "/big"); err == nil || err.(*Error).Code != CodeMetadataInvalid {
		t.Errorf("a body over the limit: %v", err)
	}
	// the address rules apply to what is asked for
	for _, raw := range []string{"http://127.0.0.1:1/x", "https://10.0.0.1/x", "https://u:p@example.com/", "ftp://example.com/"} {
		if _, err := f.Do(context.Background(), "GET", raw, nil, nil); err == nil || err.(*Error).Code != CodeAddressRefused {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestTokenRequestsSendTheClientsAuthenticationTheWayEachMethodSays(t *testing.T) {
	var got *http.Request
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		_ = r.ParseForm()
		form = r.PostForm
		_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer"}`))
	}))
	defer srv.Close()
	origin := strings.TrimPrefix(srv.URL, "http://")
	f := &Fetcher{HTTP: egress.NewClient(egress.Options{TestOrigins: map[string]bool{origin: true}}), TestOrigins: map[string]bool{origin: true}}
	for _, c := range []struct {
		ca                ClientAuth
		basic, id, secret string
	}{
		{ClientAuth{ID: "my client", Secret: "p@ss word", Method: AuthBasic}, "my+client:p%40ss+word", "", ""}, // RFC 6749 section 2.3.1: form-urlencoded first
		{ClientAuth{ID: "c", Secret: "s", Method: AuthPost}, "", "c", "s"},
		{ClientAuth{ID: "https://w.example.com/c.json", Method: AuthNone}, "", "https://w.example.com/c.json", ""},
	} {
		if _, err := f.TokenRequest(context.Background(), srv.URL+"/token", c.ca, url.Values{"grant_type": {"x"}}); err != nil {
			t.Fatal(err)
		}
		user, pass, ok := got.BasicAuth()
		if c.basic != "" && (!ok || user+":"+pass != c.basic && !strings.HasPrefix(got.Header.Get("Authorization"), "Basic ")) {
			t.Errorf("%+v: %v", c.ca, got.Header)
		}
		if c.basic == "" && got.Header.Get("Authorization") != "" || form.Get("client_id") != c.id || form.Get("client_secret") != c.secret {
			t.Errorf("%+v: %v %v", c.ca, got.Header, form)
		}
		if got.Header.Get("Cache-Control") != "no-store" || got.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("%v", got.Header)
		}
	}
}
