package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"idp-mcp-bridge/internal/auth"
)

func do(h http.Handler, method, path, bearer, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		r.Header.Set("Authorization", bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

var routes = [][2]string{
	{"GET", "/internal/v1/connections"},
	{"POST", "/internal/v1/connections/github/authorization"},
	{"POST", "/internal/v1/connections/github/callback"},
	{"DELETE", "/internal/v1/connections/github/grant"},
}

func TestWithoutATokenEveryRouteIsUnauthenticatedAndTheServiceIsNotCalled(t *testing.T) {
	called := 0
	h := New(authFunc(func(context.Context, string) (auth.Subject, error) { called++; return auth.Subject{}, nil }), Unimplemented{})
	for _, r := range routes {
		for _, header := range []string{"", "Basic abc", "Bearer", "Bearer  ", "bearer abc"} {
			if w := do(h, r[0], r[1], header, `{}`); w.Code != 401 || w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Errorf("%v %q: %d", r, header, w.Code)
			}
		}
	}
	if called != 0 {
		t.Fatalf("the authenticator was asked %d times for requests with no token", called)
	}
}

type authFunc func(context.Context, string) (auth.Subject, error)

func (f authFunc) Authenticate(ctx context.Context, b string) (auth.Subject, error) { return f(ctx, b) }

func TestB1AnswersNotImplementedForEveryRouteAndNothingIsAuthenticatedYet(t *testing.T) {
	h := New(Unimplemented{}, Unimplemented{})
	for _, r := range routes {
		if w := do(h, r[0], r[1], "Bearer some-token", `{}`); w.Code != 501 || !strings.Contains(w.Body.String(), "not_implemented") {
			t.Errorf("%v: %d %s", r, w.Code, w.Body)
		}
	}
	if w := do(h, "GET", "/internal/v1/other", "Bearer x", ""); w.Code != 404 {
		t.Errorf("an unknown route: %d", w.Code)
	}
	if w := do(h, "PUT", "/internal/v1/connections", "Bearer x", ""); w.Code != 405 {
		t.Errorf("another method: %d", w.Code)
	}
}

// What B2 will rely on: the member the service is called with is the one the authenticator named and nothing else, and
// a token that fails is 401 whatever the reason.
func TestTheServiceIsCalledWithTheMemberTheTokenNamesAndOnlyThat(t *testing.T) {
	var got []auth.Subject
	svc := recorder{&got}
	h := New(authFunc(func(_ context.Context, bearer string) (auth.Subject, error) {
		switch bearer {
		case "bob":
			return auth.Subject{Tenant: "acme", Member: "bob"}, nil
		case "no-tenant":
			return auth.Subject{Member: "x"}, nil
		}
		return auth.Subject{}, ErrUnauthenticated
	}), svc)
	// a request that names another member in the path, the query, a header and the body is still bob's
	r := httptest.NewRequest("GET", "/internal/v1/connections?member=alice&tenant=other", nil)
	r.Header.Set("Authorization", "Bearer bob")
	r.Header.Set("X-Member", "alice")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || len(got) != 1 || got[0] != (auth.Subject{Tenant: "acme", Member: "bob"}) {
		t.Fatalf("%d %v", w.Code, got)
	}
	for _, token := range []string{"forged", "no-tenant"} {
		if w := do(h, "GET", "/internal/v1/connections", "Bearer "+token, ""); w.Code != 401 || len(got) != 1 {
			t.Errorf("%s: %d", token, w.Code)
		}
	}
	if w := do(h, "POST", "/internal/v1/connections/github/callback", "Bearer bob", `not json`); w.Code != 400 {
		t.Errorf("a callback that is not JSON: %d", w.Code)
	}
}

type recorder struct{ got *[]auth.Subject }

func (r recorder) List(_ context.Context, who auth.Subject) ([]ConnectionStatus, error) {
	*r.got = append(*r.got, who)
	return []ConnectionStatus{{ID: "github", Title: "GitHub", Status: StatusNotConnected}}, nil
}
func (recorder) Start(context.Context, auth.Subject, string) (Authorization, error) {
	return Authorization{}, ErrNotImplemented
}
func (recorder) Finish(context.Context, auth.Subject, string, Finish) error { return ErrNotImplemented }
func (recorder) Disconnect(context.Context, auth.Subject, string) error     { return ErrNotImplemented }

func (recorder) ClientMetadata(string) (map[string]any, error) {
	return map[string]any{"client_id": "https://w.example.com/c.json"}, nil
}

// The client metadata document is public by design: no token, and nothing secret in it.
func TestTheClientMetadataDocumentNeedsNoTokenAndAnErrorIsAFixedCode(t *testing.T) {
	var got []auth.Subject
	h := New(authFunc(func(context.Context, string) (auth.Subject, error) { return auth.Subject{}, ErrUnauthenticated }), recorder{&got})
	if w := do(h, "GET", "/internal/v1/connections/github/client-metadata", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "client_id") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	h = New(authFunc(func(context.Context, string) (auth.Subject, error) {
		return auth.Subject{Tenant: "t", Member: "m"}, nil
	}), errSvc{})
	w := do(h, "POST", "/internal/v1/connections/github/callback", "Bearer x", `{"state":"s"}`)
	if w.Code != 400 || strings.TrimSpace(w.Body.String()) != `{"error":"authorization_failed","reason":"iss_mismatch"}` {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

type errSvc struct{ Unimplemented }

func (errSvc) Finish(context.Context, auth.Subject, string, Finish) error {
	return &Error{Status: 400, Code: "authorization_failed", Reason: "iss_mismatch"}
}
