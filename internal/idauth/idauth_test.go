package idauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"idp-mcp-bridge/internal/api"
	"idp-mcp-bridge/internal/auth"
)

const (
	issuer   = "https://keycloak.example.com/realms/idp"
	audience = "idp-mcp-bridge"
	workspc  = "idp-workspace"
)

type realm struct {
	srv   *httptest.Server
	rsa   *rsa.PrivateKey
	ec    *ecdsa.PrivateKey
	hits  atomic.Int32
	extra atomic.Pointer[rsa.PrivateKey] // a key published after a rotation
	down  atomic.Bool
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newRealm(t *testing.T) *realm {
	r := &realm{}
	r.rsa, _ = rsa.GenerateKey(rand.Reader, 2048)
	r.ec, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		if r.down.Load() {
			w.WriteHeader(503)
			return
		}
		keys := []map[string]string{
			{"kty": "RSA", "kid": "rsa1", "use": "sig", "n": enc(r.rsa.N.Bytes()), "e": enc(big.NewInt(int64(r.rsa.E)).Bytes())},
			{"kty": "EC", "kid": "ec1", "use": "sig", "crv": "P-256", "x": enc(r.ec.X.Bytes()), "y": enc(r.ec.Y.Bytes())},
			{"kty": "RSA", "kid": "enc1", "use": "enc", "n": enc(r.rsa.N.Bytes()), "e": "AQAB"},
		}
		if k := r.extra.Load(); k != nil {
			keys = append(keys, map[string]string{"kty": "RSA", "kid": "rsa2", "use": "sig", "n": enc(k.N.Bytes()), "e": enc(big.NewInt(int64(k.E)).Bytes())})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *realm) verifier() *Verifier {
	return &Verifier{Issuer: issuer, Audience: audience, AuthorizedParty: workspc, TenantClaim: "tenant_id", Keys: &JWKS{URL: r.srv.URL, HTTP: r.srv.Client(), MinRefresh: time.Millisecond}}
}

func claims(mod func(jwt.MapClaims)) jwt.MapClaims {
	c := jwt.MapClaims{"iss": issuer, "aud": []string{audience}, "azp": workspc, "sub": "bob-uuid", "tenant_id": "acme", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()}
	if mod != nil {
		mod(c)
	}
	return c
}

func sign(t *testing.T, m jwt.SigningMethod, key any, kid string, c jwt.MapClaims) string {
	tok := jwt.NewWithClaims(m, c)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ADR-0001 D28: the token is the member's own, exchanged for this audience, issued to the Workspace, signed by the realm.
func TestTheWorkspacesExchangedTokenIsVerifiedAndNamesTheMember(t *testing.T) {
	r := newRealm(t)
	v := r.verifier()
	for name, tok := range map[string]string{"RS256": sign(t, jwt.SigningMethodRS256, r.rsa, "rsa1", claims(nil)), "ES256": sign(t, jwt.SigningMethodES256, r.ec, "ec1", claims(nil)),
		"a single audience": sign(t, jwt.SigningMethodRS256, r.rsa, "rsa1", claims(func(c jwt.MapClaims) { c["aud"] = audience })),
		"several audiences": sign(t, jwt.SigningMethodRS256, r.rsa, "rsa1", claims(func(c jwt.MapClaims) { c["aud"] = []string{"account", audience} }))} {
		who, err := v.Authenticate(context.Background(), tok)
		if err != nil || who != (auth.Subject{Tenant: "acme", Member: "bob-uuid"}) {
			t.Errorf("%s: %+v %v", name, who, err)
		}
	}
}

func TestEverythingElseIsUnauthenticatedWithoutSayingWhy(t *testing.T) {
	r := newRealm(t)
	v := r.verifier()
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	rs := func(c jwt.MapClaims) string { return sign(t, jwt.SigningMethodRS256, r.rsa, "rsa1", c) }
	cases := map[string]string{
		"another issuer":                  rs(claims(func(c jwt.MapClaims) { c["iss"] = issuer + "/" })),
		"another audience":                rs(claims(func(c jwt.MapClaims) { c["aud"] = []string{"idp-host"} })),
		"no audience":                     rs(claims(func(c jwt.MapClaims) { delete(c, "aud") })),
		"issued to another client":        rs(claims(func(c jwt.MapClaims) { c["azp"] = "workspace-shell" })),
		"no authorized party":             rs(claims(func(c jwt.MapClaims) { delete(c, "azp") })),
		"expired":                         rs(claims(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() })),
		"no expiry":                       rs(claims(func(c jwt.MapClaims) { delete(c, "exp") })),
		"no subject":                      rs(claims(func(c jwt.MapClaims) { delete(c, "sub") })),
		"no tenant":                       rs(claims(func(c jwt.MapClaims) { delete(c, "tenant_id") })),
		"an empty tenant":                 rs(claims(func(c jwt.MapClaims) { c["tenant_id"] = "" })),
		"a tenant that is not a string":   rs(claims(func(c jwt.MapClaims) { c["tenant_id"] = 5 })),
		"signed by another key":           sign(t, jwt.SigningMethodRS256, other, "rsa1", claims(nil)),
		"an unknown kid":                  sign(t, jwt.SigningMethodRS256, r.rsa, "nope", claims(nil)),
		"an encryption key":               sign(t, jwt.SigningMethodRS256, r.rsa, "enc1", claims(nil)),
		"HS256 keyed with the public key": sign(t, jwt.SigningMethodHS256, []byte("anything"), "rsa1", claims(nil)),
		"alg none": func() string {
			s, _ := jwt.NewWithClaims(jwt.SigningMethodNone, claims(nil)).SignedString(jwt.UnsafeAllowNoneSignatureType)
			return s
		}(),
		"garbage": "not.a.jwt",
		"empty":   "",
	}
	for name, tok := range cases {
		if _, err := v.Authenticate(context.Background(), tok); !errors.Is(err, api.ErrUnauthenticated) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAKeyPublishedAfterARotationIsFoundAndAnUnreachableRealmAuthenticatesNobodyNewButKnownKeysKeepWorking(t *testing.T) {
	r := newRealm(t)
	v := r.verifier()
	if _, err := v.Authenticate(context.Background(), sign(t, jwt.SigningMethodRS256, r.rsa, "rsa1", claims(nil))); err != nil {
		t.Fatal(err)
	}
	k2, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := sign(t, jwt.SigningMethodRS256, k2, "rsa2", claims(nil))
	if _, err := v.Authenticate(context.Background(), tok); err == nil {
		t.Fatal("a key that was not published")
	}
	r.extra.Store(k2)
	time.Sleep(5 * time.Millisecond)
	if _, err := v.Authenticate(context.Background(), tok); err != nil {
		t.Fatalf("the rotated key: %v", err)
	}
	r.down.Store(true)
	if _, err := v.Authenticate(context.Background(), sign(t, jwt.SigningMethodRS256, r.rsa, "rsa1", claims(nil))); err != nil {
		t.Fatalf("a key already known, with the realm down: %v", err)
	}
	fresh := r.verifier()
	if _, err := fresh.Authenticate(context.Background(), sign(t, jwt.SigningMethodRS256, r.rsa, "rsa1", claims(nil))); !errors.Is(err, api.ErrUnauthenticated) {
		t.Fatalf("no keys and no realm: %v", err)
	}
}

func TestTheVerifierIsTheAPIsAuthenticatorAndAnUnauthenticatedCallIs401(t *testing.T) {
	r := newRealm(t)
	h := api.New(r.verifier(), api.Unimplemented{})
	call := func(bearer string) int {
		req := httptest.NewRequest("GET", "/internal/v1/connections", nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if c := call(""); c != 401 {
		t.Fatal(c)
	}
	if c := call(sign(t, jwt.SigningMethodRS256, r.rsa, "rsa1", claims(func(c jwt.MapClaims) { c["azp"] = "someone-else" }))); c != 401 {
		t.Fatal(c)
	}
	// verified: it gets as far as the service, which B1's stand-in answers 501
	if c := call(sign(t, jwt.SigningMethodRS256, r.rsa, "rsa1", claims(nil))); c != 501 {
		t.Fatal(c)
	}
}

// ADR-0001 D33: who may authorize reviewer accounts is a realm role (and, if configured, a tenant), with no default.
func TestTheReviewerRoleAndTenantMakeAReviewerAndNothingElseDoes(t *testing.T) {
	r := newRealm(t)
	tok := func(mod func(jwt.MapClaims)) string {
		return sign(t, jwt.SigningMethodRS256, r.rsa, "rsa1", claims(mod))
	}
	roles := func(rs ...string) func(jwt.MapClaims) { return func(c jwt.MapClaims) { c["roles"] = rs } }
	who := func(v *Verifier, token string) auth.Subject {
		s, err := v.Authenticate(context.Background(), token)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	v := r.verifier()
	if who(v, tok(roles("idp-reviewer"))).Reviewer {
		t.Fatal("with no role configured, no one is a reviewer")
	}
	v.ReviewerRole = "idp-reviewer"
	for name, c := range map[string]struct {
		mod  func(jwt.MapClaims)
		want bool
	}{
		"the role":                      {roles("host-user", "idp-reviewer"), true},
		"another role":                  {roles("host-user", "idp-reviewer-x"), false},
		"no roles claim":                {nil, false},
		"roles that are not a list":     {func(c jwt.MapClaims) { c["roles"] = "idp-reviewer" }, false},
		"a list that is not of strings": {func(c jwt.MapClaims) { c["roles"] = []any{5, nil} }, false},
	} {
		if got := who(v, tok(c.mod)).Reviewer; got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
	// the tenant narrows it
	v.ReviewerTenant = "acme"
	if !who(v, tok(roles("idp-reviewer"))).Reviewer {
		t.Fatal("the tenant of the operators")
	}
	if who(v, tok(func(c jwt.MapClaims) { c["roles"] = []string{"idp-reviewer"}; c["tenant_id"] = "other" })).Reviewer {
		t.Fatal("the role of another tenant")
	}
	// the claim is configurable
	v.RolesClaim = "realm_roles"
	if who(v, tok(roles("idp-reviewer"))).Reviewer || !who(v, tok(func(c jwt.MapClaims) { c["realm_roles"] = []string{"idp-reviewer"} })).Reviewer {
		t.Fatal("the roles claim")
	}
}
