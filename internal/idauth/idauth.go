// Package idauth verifies the token the Workspace calls the internal API with (ADR-0001 D16, D28): the member's own token,
// exchanged for the bridge's audience (RFC 8693; idp-workspace internal/dispatch/exchange.go), signed by Keycloak. The bridge
// verifies it itself, against Keycloak's keys, as the idp-mcp gateway verifies its own callers' tokens (adapters/identity).
package idauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"idp-mcp-bridge/internal/api"
	"idp-mcp-bridge/internal/auth"
)

// algorithms accepted: asymmetric only (a shared-secret algorithm would let anyone who knows a key id mint a token).
var algorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// Verifier is the Authenticator of the API.
type Verifier struct {
	// Issuer is the realm's issuer, compared character for character.
	Issuer string
	// Audience is what the token must have been exchanged for: this bridge, as Keycloak's token exchange names it.
	Audience string
	// AuthorizedParty is the client the token was issued to (azp): the Workspace's, and no other. Without it a token that
	// any other client of the realm got for the bridge's audience would be accepted.
	AuthorizedParty string
	// TenantClaim is the claim that holds the tenant (the gateway's tenantClaim).
	TenantClaim string
	Keys        *JWKS
	Leeway      time.Duration
	// ReviewerRole is the realm role (in RolesClaim) that makes a caller an operator who may authorize reviewer accounts; empty: no
	// one. ReviewerTenant, if set, is the only tenant whose holders of the role are (ADR-0001 D33).
	ReviewerRole, ReviewerTenant string
	RolesClaim                   string // default "roles"
}

// Authenticate verifies a bearer token and returns the member it names: the subject and the tenant claim. Every failure is
// ErrUnauthenticated, whatever the reason (the reason is not for the caller).
func (v *Verifier) Authenticate(ctx context.Context, bearer string) (auth.Subject, error) {
	claims := jwt.MapClaims{}
	leeway := v.Leeway
	if leeway == 0 {
		leeway = 30 * time.Second
	}
	_, err := jwt.ParseWithClaims(bearer, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return v.Keys.Key(ctx, kid)
	}, jwt.WithValidMethods(algorithms), jwt.WithIssuer(v.Issuer), jwt.WithAudience(v.Audience), jwt.WithExpirationRequired(), jwt.WithLeeway(leeway))
	if err != nil {
		return auth.Subject{}, api.ErrUnauthenticated
	}
	sub, _ := claims["sub"].(string)
	tenant, _ := claims[v.TenantClaim].(string)
	azp, _ := claims["azp"].(string)
	if sub == "" || tenant == "" || azp == "" || azp != v.AuthorizedParty {
		return auth.Subject{}, api.ErrUnauthenticated
	}
	who := auth.Subject{Tenant: tenant, Member: sub}
	if v.ReviewerRole != "" && (v.ReviewerTenant == "" || v.ReviewerTenant == tenant) {
		claim := v.RolesClaim
		if claim == "" {
			claim = "roles"
		}
		if roles, ok := claims[claim].([]any); ok {
			for _, r := range roles {
				if s, _ := r.(string); s == v.ReviewerRole {
					who.Reviewer = true
				}
			}
		}
	}
	return who, nil
}

// JWKS fetches and caches the signing keys of the realm.
type JWKS struct {
	URL        string
	HTTP       *http.Client
	TTL        time.Duration // how long a fetched key set is trusted (default 10 minutes)
	MinRefresh time.Duration // an unknown kid triggers at most one fetch in this long (default 30 seconds)

	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
	lastTry   time.Time
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func (k jwk) public() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err1 := b64(k.N)
		e, err2 := b64(k.E)
		if err1 != nil || err2 != nil || len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("bad RSA key")
		}
		ev := 0
		for _, b := range e {
			ev = ev<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: ev}, nil
	case "EC":
		curve := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}[k.Crv]
		x, err1 := b64(k.X)
		y, err2 := b64(k.Y)
		if curve == nil || err1 != nil || err2 != nil {
			return nil, errors.New("bad EC key")
		}
		return ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}

func (j *JWKS) fetch(ctx context.Context) (map[string]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := j.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if json.Unmarshal(body, &set) != nil {
		return nil, errors.New("JWKS is not a key set")
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if pk, err := k.public(); err == nil {
			keys[k.Kid] = pk // a key that cannot be used is simply not trusted
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS has no usable signing keys")
	}
	return keys, nil
}

// Key returns the key for kid, refreshing the set when it is stale or the kid is unknown (a rotation).
func (j *JWKS) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	ttl, min := j.TTL, j.MinRefresh
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	if min == 0 {
		min = 30 * time.Second
	}
	now := time.Now()
	k, known := j.keys[kid]
	if known && now.Sub(j.fetchedAt) < ttl {
		return k, nil
	}
	if now.Sub(j.lastTry) >= min || j.keys == nil {
		j.lastTry = now
		fctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		keys, err := j.fetch(fctx)
		cancel()
		if err == nil {
			j.keys, j.fetchedAt = keys, now
			k, known = keys[kid]
		}
	}
	if !known {
		return nil, errors.New("unknown signing key")
	}
	return k, nil
}
