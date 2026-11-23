package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"idp-mcp-bridge/internal/api"
	"idp-mcp-bridge/internal/auth"
	"idp-mcp-bridge/internal/config"
	"idp-mcp-bridge/internal/grants"
)

// Defaults of Service.
const (
	StateTTL       = 10 * time.Minute // an authorization that is not finished in this long is forgotten (ADR-0001 D23)
	RefreshWindow  = 60 * time.Second // a token this close to its expiry is renewed before it is used (D26)
	RefreshTimeout = 15 * time.Second // one call to a token endpoint, with the grant's row locked
)

// Service is the OAuth side of the bridge: the TokenSource the calls use, the step-up hook, and the api.Service the Workspace
// calls. It is safe for concurrent use and keeps no state of its own besides the discovery cache: the grants and the pending
// authorizations are in the store, so any replica can finish what another started and renew what another stored.
type Service struct {
	Connections []config.Connection
	// RedirectURI is the Workspace's callback page, for every connection (ADR-0001 D23). It is configuration, never a field
	// of a request.
	RedirectURI string
	Store       grants.Store
	Sealer      grants.Sealer
	Disc        *Discoverer
	F           *Fetcher
	Log         *slog.Logger
	Now         func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) conn(id string) (config.Connection, bool) {
	for _, c := range s.Connections {
		if c.ID == id && c.Authorization.Mode == config.AuthOAuth {
			return c, true
		}
	}
	return config.Connection{}, false
}

func (s *Service) logf(msg string, who auth.Subject, c config.Connection, err error) {
	if s.Log == nil {
		return
	}
	// the code only: what the other side said, and every secret, stay out of the log
	code := "internal"
	var oe *Error
	if errors.As(err, &oe) {
		code = oe.Code
	}
	s.Log.Warn(msg, "connection", c.ID, "tenant", who.Tenant, "code", code)
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hash(state string) []byte {
	h := sha256.Sum256([]byte(state))
	return h[:]
}

func owner(who auth.Subject, c string) grants.Key {
	return grants.Key{Tenant: who.Tenant, Member: who.Member, Connection: c}
}

// reviewerKey is the key of a connection's reviewer grant (ADR-0001 D33): the connection's, not any member's.
func reviewerKey(c string) grants.Key { return grants.Key{Connection: c, Reviewer: true} }

func forbidden() error { return apiErr(http.StatusForbidden, "forbidden") }

// union is the scopes of a followed by those of b that a does not have, in order (SEP-2350: a step-up asks for what was
// granted and what is now needed).
func union(a, b string) string {
	out := strings.Fields(a)
	for _, x := range strings.Fields(b) {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return strings.Join(out, " ")
}

// ---- the client's identity ----

// clientAuth works out who the bridge is at the authorization server and how it proves it, for a connection (ADR-0001 D22).
func (s *Service) clientAuth(ctx context.Context, c config.Connection, d *Discovered) (ClientAuth, error) {
	cl := c.Authorization.Client
	switch cl.Mode {
	case config.ClientPreregistered:
		b, err := os.ReadFile(cl.SecretFile)
		if err != nil || strings.TrimSpace(string(b)) == "" {
			return ClientAuth{}, fail(CodeClientUnsupported, "the client secret file cannot be read")
		}
		// RFC 8414 section 2: absent, the default is client_secret_basic
		methods := d.AS.TokenAuthMethods
		method := AuthBasic
		switch {
		case len(methods) == 0 || slices.Contains(methods, AuthBasic):
		case slices.Contains(methods, AuthPost):
			method = AuthPost
		default:
			return ClientAuth{}, fail(CodeClientUnsupported, "the server accepts neither client_secret_basic nor client_secret_post")
		}
		return ClientAuth{ID: cl.ID, Secret: strings.TrimSpace(string(b)), Method: method}, nil
	case config.ClientCIMD:
		if d.AS.CIMD {
			return ClientAuth{ID: cl.Document, Method: AuthNone}, nil
		}
		if cl.DynamicRegistration && d.AS.RegistrationEndpoint != "" {
			return s.dynamicClient(ctx, c, d)
		}
		return ClientAuth{}, fail(CodeClientUnsupported, "the server does not support client metadata documents, and dynamic registration is not enabled for the connection")
	}
	return ClientAuth{}, fail(CodeClientUnsupported, "no client identity")
}

func (s *Service) dynamicClient(ctx context.Context, c config.Connection, d *Discovered) (ClientAuth, error) {
	k := grants.Key{Connection: c.ID}
	reg, err := s.Store.GetRegistration(ctx, c.ID, c.Authorization.Issuer, s.RedirectURI)
	if err == nil {
		ca := ClientAuth{ID: reg.ClientID, Method: reg.AuthMethod}
		if len(reg.SealedSecret) > 0 {
			sec, err := s.Sealer.Open(reg.SealedSecret, k)
			if err != nil {
				return ClientAuth{}, err
			}
			ca.Secret = string(sec)
		}
		return ca, nil
	}
	if !errors.Is(err, grants.ErrNotFound) {
		return ClientAuth{}, err
	}
	r, err := s.F.Register(ctx, d.AS.RegistrationEndpoint, c.Title, s.RedirectURI)
	if err != nil {
		return ClientAuth{}, err
	}
	row := grants.Registration{Connection: c.ID, Issuer: c.Authorization.Issuer, RedirectURI: s.RedirectURI, ClientID: r.ClientID, AuthMethod: r.AuthMethod}
	if r.Secret != "" {
		if row.SealedSecret, err = s.Sealer.Seal([]byte(r.Secret), k); err != nil {
			return ClientAuth{}, err
		}
	}
	if err := s.Store.PutRegistration(ctx, row); err != nil {
		return ClientAuth{}, err
	}
	return ClientAuth{ID: r.ClientID, Secret: r.Secret, Method: r.AuthMethod}, nil
}

// ClientMetadata is the client metadata document of a cimd connection, built from the configuration: the client_id is the
// document's own address, so it cannot disagree with what the bridge sends (ADR-0001 D22).
func (s *Service) ClientMetadata(id string) (map[string]any, error) {
	c, ok := s.conn(id)
	if !ok || c.Authorization.Client.Mode != config.ClientCIMD {
		return nil, &api.Error{Status: http.StatusNotFound, Code: "not_found"}
	}
	return map[string]any{
		"client_id":                  c.Authorization.Client.Document,
		"client_name":                c.Title,
		"redirect_uris":              []string{s.RedirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": AuthNone,
	}, nil
}

// ---- starting an authorization ----

func apiErr(status int, code string) error { return &api.Error{Status: status, Code: code} }

// discoveryErr maps a failure of discovery or of the client's identity to the Workspace's answer: a fixed code, 502 if the
// third party is to blame and could do better, 409 if the connection's configuration and the third party's metadata disagree.
func discoveryErr(err error) error {
	var e *Error
	if errors.As(err, &e) {
		if e.Transient {
			return apiErr(http.StatusBadGateway, "authorization_server_unavailable")
		}
		return &api.Error{Status: http.StatusConflict, Code: "authorization_server_refused", Reason: e.Code}
	}
	return apiErr(http.StatusInternalServerError, "internal")
}

// Start makes the address the member's browser is sent to (ADR-0001 D23): PKCE S256, a state of 32 random bytes kept
// server-side with who started it, the resource of RFC 8707. The member is the one the authenticated token names.
func (s *Service) Start(ctx context.Context, who auth.Subject, id string) (api.Authorization, error) {
	return s.start(ctx, who, id, false)
}

// StartReviewer starts the authorization of the connection's reviewer account (ADR-0001 D33): the same flow, for an operator whose
// token carries the reviewer role, and the grant it ends in is the connection's, not the operator's own.
func (s *Service) StartReviewer(ctx context.Context, who auth.Subject, id string) (api.Authorization, error) {
	if !who.Reviewer {
		return api.Authorization{}, forbidden()
	}
	return s.start(ctx, who, id, true)
}

func (s *Service) start(ctx context.Context, who auth.Subject, id string, reviewer bool) (api.Authorization, error) {
	c, ok := s.conn(id)
	if !ok {
		return api.Authorization{}, apiErr(http.StatusNotFound, "not_found")
	}
	d, err := s.Disc.Get(ctx, c)
	if err != nil {
		s.logf("authorization not started", who, c, err)
		return api.Authorization{}, discoveryErr(err)
	}
	ca, err := s.clientAuth(ctx, c, d)
	if err != nil {
		s.logf("authorization not started", who, c, err)
		return api.Authorization{}, discoveryErr(err)
	}
	scope := strings.Join(c.Authorization.Scopes, " ")
	if reviewer && len(c.Authorization.ReviewerScopes) > 0 {
		scope = strings.Join(c.Authorization.ReviewerScopes, " ") // the least that lets the account list the tools
	}
	if scope == "" && c.Authorization.ScopesFromResource {
		// only on the operator's explicit opt-in: by default no scopes configured means none requested (ADR-0001 D37)
		scope = strings.Join(d.PRMScopes, " ")
	}
	// after a step-up the member authorizes again for what was granted and what the third party now asks for
	if g, err := s.Store.Get(ctx, owner(who, id)); !reviewer && err == nil && g.NeededScope != "" {
		scope = union(scope, g.NeededScope)
	}
	prompt := false
	if scope != "" && slices.Contains(d.AS.ScopesSupported, "offline_access") && !slices.Contains(strings.Fields(scope), "offline_access") {
		scope += " offline_access" // SEP-2207: the server issues refresh tokens for this scope
		prompt = true
	} else if slices.Contains(strings.Fields(scope), "offline_access") {
		prompt = true
	}
	state, err := randomString(32)
	if err != nil {
		return api.Authorization{}, err
	}
	verifier, err := randomString(32) // 43 characters, RFC 7636 section 4.1
	if err != nil {
		return api.Authorization{}, err
	}
	stateKey := owner(who, id)
	stateKey.Reviewer = reviewer // the verifier is sealed for this kind of authorization and no other
	sealed, err := s.Sealer.Seal([]byte(verifier), stateKey)
	if err != nil {
		return api.Authorization{}, err
	}
	resource := c.Parsed.URL()
	err = s.Store.PutState(ctx, grants.State{Hash: hash(state), Key: stateKey, SealedVerifier: sealed, Issuer: c.Authorization.Issuer,
		RedirectURI: s.RedirectURI, Scope: scope, ClientID: ca.ID, Resource: resource, Expires: s.now().Add(StateTTL)})
	if err != nil {
		return api.Authorization{}, err
	}
	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {ca.ID}, "redirect_uri": {s.RedirectURI}, "state": {state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}, "resource": {resource}}
	if scope != "" {
		q.Set("scope", scope)
	}
	if prompt {
		q.Set("prompt", "consent") // OpenID Connect Core 11: asked for with offline_access
	}
	u, err := url.Parse(d.AS.AuthorizationEndpoint)
	if err != nil {
		return api.Authorization{}, err
	}
	if u.RawQuery != "" {
		u.RawQuery += "&" + q.Encode()
	} else {
		u.RawQuery = q.Encode()
	}
	return api.Authorization{URL: u.String()}, nil
}

// authorizationErrors is the set of codes the member is told about when the authorization server refuses (RFC 6749 section
// 4.1.2.1); anything else is authorization_failed. The error_description is never read.
var authorizationErrors = map[string]bool{"access_denied": true, "invalid_scope": true, "server_error": true, "temporarily_unavailable": true,
	"invalid_request": true, "unauthorized_client": true, "unsupported_response_type": true}

// Finish completes an authorization: the state is consumed before anything else is done with the code (one use), must be
// the caller's, and the callback's iss must be the pinned issuer (RFC 9207).
func (s *Service) Finish(ctx context.Context, who auth.Subject, id string, f api.Finish) error {
	if len(f.State) == 0 || len(f.State) > 256 || len(f.Code) > 4096 || len(f.Iss) > 2048 || len(f.Error) > 256 {
		return apiErr(http.StatusBadRequest, "invalid_request")
	}
	c, ok := s.conn(id)
	if !ok {
		return apiErr(http.StatusNotFound, "not_found")
	}
	// consumed here, in one statement, and only if it is the caller's: a state presented by anyone else is not used up, and
	// is not told apart from one that never existed
	st, err := s.Store.TakeState(ctx, hash(f.State), who.Tenant, who.Member)
	if errors.Is(err, grants.ErrNotFound) {
		return apiErr(http.StatusBadRequest, "invalid_state")
	}
	if err != nil {
		return err
	}
	if st.Reviewer && !who.Reviewer {
		return forbidden() // the role was taken away since the authorization started
	}
	switch {
	case st.Connection != id:
		return apiErr(http.StatusBadRequest, "invalid_state") // the page's connection is not the one that was started
	case !s.now().Before(st.Expires):
		return apiErr(http.StatusBadRequest, "state_expired")
	case st.Issuer != c.Authorization.Issuer || st.RedirectURI != s.RedirectURI:
		return apiErr(http.StatusConflict, "configuration_changed")
	}
	d, err := s.Disc.Get(ctx, c)
	if err != nil {
		s.logf("authorization not finished", who, c, err)
		return discoveryErr(err)
	}
	// RFC 9207: an iss, if there is one, is the pinned issuer; one is required where the server says it sends one
	switch {
	case f.Iss != "" && f.Iss != c.Authorization.Issuer:
		s.logf("authorization refused: iss", who, c, fail("iss_mismatch", ""))
		return &api.Error{Status: http.StatusBadRequest, Code: "authorization_failed", Reason: "iss_mismatch"}
	case f.Iss == "" && d.AS.IssParameter:
		return &api.Error{Status: http.StatusBadRequest, Code: "authorization_failed", Reason: "iss_missing"}
	}
	if f.Error != "" {
		reason := "authorization_failed"
		if authorizationErrors[f.Error] {
			reason = f.Error
		}
		return &api.Error{Status: http.StatusBadRequest, Code: "authorization_denied", Reason: reason}
	}
	if f.Code == "" {
		return apiErr(http.StatusBadRequest, "invalid_request")
	}
	verifier, err := s.Sealer.Open(st.SealedVerifier, st.Key)
	if err != nil {
		return err
	}
	ca, err := s.clientAuth(ctx, c, d)
	if err != nil {
		s.logf("authorization not finished", who, c, err)
		return discoveryErr(err)
	}
	if ca.ID != st.ClientID {
		return apiErr(http.StatusConflict, "configuration_changed")
	}
	tctx, cancel := context.WithTimeout(ctx, RefreshTimeout)
	defer cancel()
	tok, err := s.F.TokenRequest(tctx, d.AS.TokenEndpoint, ca, url.Values{"grant_type": {"authorization_code"}, "code": {f.Code},
		"redirect_uri": {st.RedirectURI}, "code_verifier": {string(verifier)}, "resource": {st.Resource}})
	if err != nil {
		s.logf("authorization not finished", who, c, err)
		var e *Error
		if errors.As(err, &e) && e.Transient {
			s.Disc.Drop(c.ID)
			return apiErr(http.StatusBadGateway, "authorization_server_unavailable")
		}
		reason := "token_endpoint_error"
		if errors.As(err, &e) && e.Code == CodeInvalidGrant {
			reason = CodeInvalidGrant
		} else if errors.As(err, &e) && e.Code == CodeTokenResponse {
			reason = CodeTokenResponse
		}
		return &api.Error{Status: http.StatusBadGateway, Code: "authorization_failed", Reason: reason}
	}
	granted := tok.Scope
	if granted == "" {
		granted = st.Scope // RFC 6749 section 5.1: omitted, it is what was requested
	}
	key, by := owner(who, id), ""
	if st.Reviewer {
		key, by = reviewerKey(id), who.Tenant+"/"+who.Member // the connection's reviewer grant; never the operator's own
	}
	g, err := s.seal(grants.Grant{Key: key, Issuer: c.Authorization.Issuer, Scope: granted, CreatedAt: s.now(), RefreshedAt: s.now(), AuthorizedBy: by}, tok)
	if err != nil {
		return err
	}
	old, oerr := s.Store.Get(ctx, key) // the grant this one supersedes, if any
	if err := s.Store.Put(ctx, g); err != nil {
		return err
	}
	// The new grant is stored, and what happens next cannot undo it: the superseded tokens are revoked at the server, best effort
	// (ADR-0001 D35), with no row locked. Tokens the server happened to issue again are not revoked, and neither are those of an
	// authorization server that is no longer the connection's: a token is shown only to the server that issued it.
	if oerr == nil && old.Issuer == c.Authorization.Issuer {
		s.revoke(ctx, who, c, old, tok.Access, tok.Refresh)
	}
	return nil
}

// seal puts a token response into a grant, under the current key.
func (s *Service) seal(g grants.Grant, tok Tokens) (grants.Grant, error) {
	var err error
	if g.SealedAccess, err = s.Sealer.Seal([]byte(tok.Access), g.Key); err != nil {
		return g, err
	}
	g.SealedRefresh = nil
	if tok.Refresh != "" {
		if g.SealedRefresh, err = s.Sealer.Seal([]byte(tok.Refresh), g.Key); err != nil {
			return g, err
		}
	}
	g.AccessExpires = time.Time{}
	if tok.ExpiresIn > 0 {
		g.AccessExpires = s.now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	return g, nil
}

// ---- the token source ----

// Token returns the member's access token for a connection, renewing it first if it is within RefreshWindow of its expiry.
// ErrNoToken if there is no grant, it was made for another issuer, it needs the member to authorize again, it has expired
// with no refresh token, or its refresh token was refused.
func (s *Service) Token(ctx context.Context, who auth.Subject, id string) (string, error) {
	c, ok := s.conn(id)
	if !ok {
		return "", auth.ErrNoToken
	}
	return s.token(ctx, owner(who, id), who, c)
}

// token is Token for a grant of any kind: a member's, or a connection's reviewer grant.
func (s *Service) token(ctx context.Context, key grants.Key, who auth.Subject, c config.Connection) (string, error) {
	g, err := s.Store.Get(ctx, key)
	if errors.Is(err, grants.ErrNotFound) {
		return "", auth.ErrNoToken
	}
	if err != nil {
		return "", err
	}
	if g.Issuer != c.Authorization.Issuer || g.ReauthReason != "" {
		return "", auth.ErrNoToken
	}
	if g.AccessExpires.IsZero() || g.AccessExpires.Sub(s.now()) > RefreshWindow {
		t, err := s.Sealer.Open(g.SealedAccess, g.Key)
		return string(t), err
	}
	return s.renew(ctx, key, who, c, "")
}

// ReviewerSource is the connections' reviewer accounts as the auth.ReviewerSource of the bridge: the token for tools/list
// (registration, review, drift probes) and for nothing else (ADR-0001 D33).
type ReviewerSource struct{ S *Service }

// Token is the reviewer account's token, renewed like a member's (the same row lock, the same rotation), "" for a connection
// that needs none, auth.ErrNoToken if the connection has no usable reviewer grant.
func (r ReviewerSource) Token(ctx context.Context, connection string) (string, error) {
	c, ok := r.S.conn(connection)
	if !ok {
		return "", nil
	}
	return r.S.token(ctx, reviewerKey(connection), auth.Subject{}, c)
}

// Refresh is asked after the third party refused rejected, the reviewer's token.
func (r ReviewerSource) Refresh(ctx context.Context, connection, rejected string) (string, error) {
	c, ok := r.S.conn(connection)
	if !ok {
		return "", auth.ErrNoToken
	}
	return r.S.renew(ctx, reviewerKey(connection), auth.Subject{}, c, rejected)
}

var _ auth.ReviewerSource = ReviewerSource{}
var _ auth.ReviewerRefresher = ReviewerSource{}

// Refresh is asked after the third party answered 401 to rejected: a new access token, from the refresh token, or ErrNoToken.
func (s *Service) Refresh(ctx context.Context, who auth.Subject, id, rejected string) (string, error) {
	c, ok := s.conn(id)
	if !ok {
		return "", auth.ErrNoToken
	}
	return s.renew(ctx, owner(who, id), who, c, rejected)
}

// renew is the one place a refresh token is spent. It runs with the grant's row locked, on whichever replica, and decides
// after it has the lock, on what is in the row then: a second caller that waited finds the first one's result and uses it, so
// a refresh token that the server invalidates when it rotates it is spent once. rejected is the access token the third
// party refused ("" for a renewal ahead of expiry).
func (s *Service) renew(ctx context.Context, key grants.Key, who auth.Subject, c config.Connection, rejected string) (string, error) {
	var token string
	var gone bool
	ctx, cancel := context.WithTimeout(ctx, RefreshTimeout+s.timeoutSlack())
	defer cancel()
	err := s.Store.Locked(ctx, key, func(g grants.Grant) (grants.Grant, grants.Action, error) {
		if g.Issuer != c.Authorization.Issuer || g.ReauthReason != "" {
			gone = true // not deleted: the member authorizes again
			return g, grants.Keep, nil
		}
		cur, err := s.Sealer.Open(g.SealedAccess, g.Key)
		if err != nil {
			return g, grants.Keep, err
		}
		expiring := !g.AccessExpires.IsZero() && g.AccessExpires.Sub(s.now()) <= RefreshWindow
		switch {
		case rejected != "" && string(cur) != rejected:
			token = string(cur) // another caller renewed it since
			return g, grants.Keep, nil
		case rejected == "" && !expiring:
			token = string(cur) // another caller renewed it while this one waited for the lock
			return g, grants.Keep, nil
		case len(g.SealedRefresh) == 0:
			if rejected == "" && g.AccessExpires.After(s.now()) {
				token = string(cur) // nothing to renew with, and it still has some time
				return g, grants.Keep, nil
			}
			gone = true
			return g, grants.Keep, nil
		}
		rt, err := s.Sealer.Open(g.SealedRefresh, g.Key)
		if err != nil {
			return g, grants.Keep, err
		}
		d, err := s.Disc.Get(ctx, c)
		if err == nil {
			var ca ClientAuth
			if ca, err = s.clientAuth(ctx, c, d); err == nil {
				var tok Tokens
				tok, err = s.F.TokenRequest(ctx, d.AS.TokenEndpoint, ca, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {string(rt)}, "resource": {c.Parsed.URL()}})
				if err == nil {
					// RFC 6749 section 6: a refresh may omit scope (unchanged) and refresh_token (not rotated); rotation, when it
					// happens, is kept: the new token replaces the old one in the same transaction as it is received
					ng := g
					if tok.Refresh == "" {
						tok.Refresh = string(rt)
					}
					if tok.Scope != "" {
						ng.Scope = tok.Scope
					}
					ng.RefreshedAt = s.now()
					if ng, err = s.seal(ng, tok); err != nil {
						return g, grants.Keep, err
					}
					token = tok.Access
					return ng, grants.Update, nil
				}
			}
		}
		var oe *Error
		switch {
		case errors.As(err, &oe) && oe.Code == CodeInvalidGrant:
			// the refresh token is no good: the grant is gone, and the member authorizes again
			gone = true
			return g, grants.Delete, nil
		case errors.As(err, &oe) && oe.Transient:
			s.Disc.Drop(c.ID)
			if rejected == "" && g.AccessExpires.After(s.now()) {
				token = string(cur) // not renewed, and not yet expired: it is still good
				return g, grants.Keep, nil
			}
		}
		s.logf("token not renewed", who, c, err)
		return g, grants.Keep, err
	})
	switch {
	case errors.Is(err, grants.ErrNotFound):
		return "", auth.ErrNoToken
	case err != nil:
		return "", err
	case gone:
		return "", auth.ErrNoToken
	}
	return token, nil
}

func (s *Service) timeoutSlack() time.Duration { return 5 * time.Second }

// InsufficientScope records that the third party asked for more scope than the grant has (a 403 with error="insufficient_scope",
// RFC 6750 section 3.1): the grant stays, is not used, and the next authorization asks for the union (ADR-0001 D27).
func (s *Service) InsufficientScope(ctx context.Context, who auth.Subject, id, scope string) error {
	if _, ok := s.conn(id); !ok {
		return nil
	}
	err := s.Store.Locked(ctx, owner(who, id), func(g grants.Grant) (grants.Grant, grants.Action, error) {
		// the third party's challenge can widen what the next authorization asks for (ADR-0001 D37): the names that are added are logged
		if s.Log != nil {
			var added []string
			for _, n := range strings.Fields(scope) {
				if validScopeName(n) && !slices.Contains(strings.Fields(g.Scope+" "+g.NeededScope), n) {
					added = append(added, n)
				}
			}
			if len(added) > 0 {
				s.Log.Info("scope asked for by the third party's challenge", "connection", id, "tenant", who.Tenant, "added", strings.Join(added, " "))
			}
		}
		g.NeededScope = union(union(g.Scope, g.NeededScope), scope)
		g.ReauthReason = grants.ReasonInsufficientScope
		return g, grants.Update, nil
	})
	if errors.Is(err, grants.ErrNotFound) {
		return nil
	}
	return err
}

// ---- disconnecting and listing ----

// Disconnect revokes the member's tokens at the authorization server if it has a revocation endpoint (RFC 7009: the refresh
// token, then the access token) and deletes the grant. It is deleted whether or not revocation worked: the member asked to be
// disconnected, and a server that is down does not keep them connected. Only the code of a failure is logged.
func (s *Service) Disconnect(ctx context.Context, who auth.Subject, id string) error {
	c, ok := s.conn(id)
	if !ok {
		return apiErr(http.StatusNotFound, "not_found")
	}
	g, err := s.Store.Get(ctx, owner(who, id))
	if errors.Is(err, grants.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	s.revoke(ctx, who, c, g)
	return s.Store.Delete(ctx, g.Key)
}

// DisconnectReviewer removes the connection's reviewer account the way a member disconnects: revoked at the server if it can be,
// deleted either way.
func (s *Service) DisconnectReviewer(ctx context.Context, who auth.Subject, id string) error {
	if !who.Reviewer {
		return forbidden()
	}
	c, ok := s.conn(id)
	if !ok {
		return apiErr(http.StatusNotFound, "not_found")
	}
	g, err := s.Store.Get(ctx, reviewerKey(id))
	if errors.Is(err, grants.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	s.revoke(ctx, who, c, g)
	return s.Store.Delete(ctx, g.Key)
}

// Revoke is Disconnect for the operator, for one grant: used by `idp-mcp-bridge revoke`.
func (s *Service) Revoke(ctx context.Context, g grants.Grant) {
	if c, ok := s.conn(g.Connection); ok {
		s.revoke(ctx, auth.Subject{Tenant: g.Tenant, Member: g.Member}, c, g)
	}
}

func (s *Service) revoke(ctx context.Context, who auth.Subject, c config.Connection, g grants.Grant, keep ...string) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	d, err := s.Disc.Get(ctx, c)
	if err != nil {
		s.logf("revocation skipped", who, c, err)
		return
	}
	if d.AS.RevocationEndpoint == "" {
		return
	}
	ca, err := s.clientAuth(ctx, c, d)
	if err != nil {
		s.logf("revocation skipped", who, c, err)
		return
	}
	for _, t := range []struct {
		sealed []byte
		hint   string
	}{{g.SealedRefresh, "refresh_token"}, {g.SealedAccess, "access_token"}} {
		if len(t.sealed) == 0 {
			continue
		}
		plain, err := s.Sealer.Open(t.sealed, g.Key)
		if err != nil {
			s.logf("revocation skipped", who, c, err)
			continue
		}
		if slices.Contains(keep, string(plain)) {
			continue // the same token is still the grant's
		}
		if err := s.F.Revoke(ctx, d.AS.RevocationEndpoint, ca, string(plain), t.hint); err != nil {
			s.logf("revocation failed", who, c, err)
		}
	}
}

// List is the Workspace's page for the member: each connection with its status. No token, and no address of an authorization
// server, is in it.
func (s *Service) List(ctx context.Context, who auth.Subject) ([]api.ConnectionStatus, error) {
	gs, err := s.Store.ForMember(ctx, who.Tenant, who.Member)
	if err != nil {
		return nil, err
	}
	by := map[string]grants.Grant{}
	for _, g := range gs {
		by[g.Connection] = g
	}
	out := make([]api.ConnectionStatus, 0, len(s.Connections))
	for _, c := range s.Connections {
		st := api.ConnectionStatus{ID: c.ID, Title: c.Title}
		g, has := by[c.ID]
		st.Status, st.Reason, st.Scope = s.statusOf(c, g, has)
		if who.Reviewer { // only a caller with the reviewer role sees it
			rs := api.ReviewerStatus{Status: api.StatusNotRequired}
			if c.Authorization.Mode == config.AuthOAuth {
				rg, rerr := s.Store.Get(ctx, reviewerKey(c.ID))
				if rerr != nil && !errors.Is(rerr, grants.ErrNotFound) {
					return nil, rerr
				}
				rs.Status, rs.Reason, rs.Scope = s.statusOf(c, rg, rerr == nil)
			}
			st.Reviewer = &rs
		}
		out = append(out, st)
	}
	return out, nil
}

// statusOf is the status of a grant (a member's or a reviewer's) of a connection, with the reason code and the granted scope.
func (s *Service) statusOf(c config.Connection, g grants.Grant, has bool) (status, reason, scope string) {
	switch {
	case c.Authorization.Mode == config.AuthNone:
		return api.StatusNotRequired, "", ""
	case !has:
		return api.StatusNotConnected, "", ""
	case g.Issuer != c.Authorization.Issuer:
		return api.StatusReauthorize, "issuer_changed", ""
	case g.ReauthReason != "":
		return api.StatusReauthorize, g.ReauthReason, g.Scope
	case len(g.SealedRefresh) == 0 && !g.AccessExpires.IsZero() && !g.AccessExpires.After(s.now()):
		return api.StatusReauthorize, "expired", g.Scope
	}
	return api.StatusConnected, "", g.Scope
}

// Sweep removes the authorizations that expired (a member who never came back from the third party's page).
func (s *Service) Sweep(ctx context.Context) (int, error) {
	return s.Store.SweepStates(ctx, s.now())
}

var _ auth.TokenSource = (*Service)(nil)
var _ api.Service = (*Service)(nil)

// validScopeName is a scope token of RFC 6749 section 3.3 of a sane length: only such names are put in a log line.
func validScopeName(n string) bool {
	return n != "" && len(n) <= 128 && !strings.ContainsFunc(n, func(r rune) bool { return r < 0x21 || r > 0x7e || r == '"' || r == '\\' })
}
