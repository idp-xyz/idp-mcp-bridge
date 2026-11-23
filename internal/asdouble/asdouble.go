// Package asdouble is a double of a third party's OAuth authorization server, for the tests: the metadata (every flag the
// bridge reads switchable), a client metadata document fetched through a test origin, an authorization endpoint that consents
// by itself, a token endpoint that checks PKCE, the redirect address, the resource and the client's authentication, refresh
// with rotation and invalidation, revocation, dynamic registration, and the ways an authorization server can go wrong: a
// wrong iss, a metadata document that names another issuer, an error answer. It records every request. It is not used by
// the service.
package asdouble

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Request is what the double received at an endpoint.
type Request struct {
	Path   string
	Header http.Header
	Form   url.Values
}

// Token is an access token the double issued.
type Token struct {
	User    string
	Scope   string
	Expires time.Time
	Revoked bool
}

type code struct {
	client, redirect, challenge, resource, scope, user string
	used                                               bool
}

type refresh struct {
	client, scope, user string
	valid               bool
}

// Server is the double.
type Server struct {
	*httptest.Server

	mu sync.Mutex
	// Metadata switches. A zero Server is a conforming one except for what New sets.
	CIMD, IssParameter, Revocation, Registration bool
	NoS256                                       bool
	AuthMethods                                  []string // token_endpoint_auth_methods_supported; nil: omitted
	ScopesSupported                              []string
	// MetadataIssuer, if set, is what the metadata says its issuer is (instead of this server's address).
	MetadataIssuer string

	// Behaviour switches.
	WrongIss, OmitIss string // the iss of the authorization response: a wrong one; OmitIss "true" sends none
	AuthError         string // answer the authorization request with this error
	ExpiresIn         int    // seconds, default 3600; negative: omit
	OmitScope, Rotate bool
	TokenType         string // default "Bearer"
	NoRefreshToken    bool
	InvalidGrant      bool // refuse every refresh with invalid_grant
	TokenError        int  // answer every token request with this HTTP status
	// CodeError200 and RefreshError200 answer the code exchange, and a refresh, with HTTP 200 and this `error` in the body: what GitHub
	// does (bad_verification_code, bad_refresh_token) instead of RFC 6749 section 5.2's 400.
	CodeError200, RefreshError200 string
	TokenDelay                    time.Duration
	AuthEndpoint                  string // what the metadata says the authorization endpoint is (default: this server's)
	RedirectMetadata              string // "same": the metadata is served after a 307 to this server's other path; any address: a 307 there
	RevokeStatus                  int    // answer every revocation with this HTTP status
	RequireResource               bool   // default true through New

	clients map[string]string // preregistered: id -> secret
	// Method is how the preregistered clients authenticate: the endpoint accepts only that one.
	Method string

	codes    map[string]*code
	refresh  map[string]*refresh
	Tokens   map[string]*Token
	nextID   int
	reqs     []Request
	Registry map[string]string // dynamically registered: id -> secret
}

// New starts a double on a loopback port; Close it.
func New() *Server {
	s := &Server{ExpiresIn: 3600, RequireResource: true, Method: "client_secret_basic", clients: map[string]string{}, codes: map[string]*code{}, refresh: map[string]*refresh{},
		Tokens: map[string]*Token{}, Registry: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.metadata)
	mux.HandleFunc("/meta2", s.metadata)
	mux.HandleFunc("/authorize", s.authorize)
	mux.HandleFunc("/token", s.token)
	mux.HandleFunc("/revoke", s.revoke)
	mux.HandleFunc("/register", s.register)
	s.Server = httptest.NewServer(mux)
	return s
}

// Issuer is this server's address, which is its issuer.
func (s *Server) Issuer() string { return s.Server.URL }

// Origin is host:port, for the test-origin exemption.
func (s *Server) Origin() string { return strings.TrimPrefix(s.Server.URL, "http://") }

// Preregister makes a client known, with its secret.
func (s *Server) Preregister(id, secret string) {
	s.mu.Lock()
	s.clients[id] = secret
	s.mu.Unlock()
}

// Requests returns what was received so far at path ("" for all).
func (s *Server) Requests(path string) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Request
	for _, r := range s.reqs {
		if path == "" || r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

// Check is what the protected resource asks of a token: whose it is and its scope, if it is good.
func (s *Server) Check(tok string) (user, scope string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.Tokens[tok]
	if t == nil || t.Revoked || time.Now().After(t.Expires) {
		return "", "", false
	}
	return t.User, t.Scope, true
}

// ExpireAll makes every access token issued so far expired.
func (s *Server) ExpireAll() {
	s.mu.Lock()
	for _, t := range s.Tokens {
		t.Expires = time.Now().Add(-time.Second)
	}
	s.mu.Unlock()
}

// InvalidateRefreshTokens makes every refresh token issued so far invalid.
func (s *Server) InvalidateRefreshTokens() {
	s.mu.Lock()
	for _, r := range s.refresh {
		r.valid = false
	}
	s.mu.Unlock()
}

// Revoked says whether an access or refresh token was revoked at the revocation endpoint.
func (s *Server) Revoked(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.Tokens[tok]; t != nil && t.Revoked {
		return true
	}
	if r := s.refresh[tok]; r != nil && !r.valid {
		return true
	}
	return false
}

func (s *Server) record(r *http.Request) {
	_ = r.ParseForm()
	s.reqs = append(s.reqs, Request{Path: r.URL.Path, Header: r.Header.Clone(), Form: r.Form})
}

func rnd(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) metadata(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record(r)
	if r.URL.Path != "/meta2" && s.RedirectMetadata != "" {
		to := s.RedirectMetadata
		if to == "same" {
			to = s.Issuer() + "/meta2"
		}
		http.Redirect(w, r, to, http.StatusTemporaryRedirect)
		return
	}
	iss := s.Issuer()
	if s.MetadataIssuer != "" {
		iss = s.MetadataIssuer
	}
	authz := s.Issuer() + "/authorize"
	if s.AuthEndpoint != "" {
		authz = s.AuthEndpoint
	}
	m := map[string]any{"issuer": iss, "authorization_endpoint": authz, "token_endpoint": s.Issuer() + "/token",
		"grant_types_supported": []string{"authorization_code", "refresh_token"}, "response_types_supported": []string{"code"}}
	if !s.NoS256 {
		m["code_challenge_methods_supported"] = []string{"S256"}
	}
	if s.AuthMethods != nil {
		m["token_endpoint_auth_methods_supported"] = s.AuthMethods
	}
	if s.ScopesSupported != nil {
		m["scopes_supported"] = s.ScopesSupported
	}
	if s.CIMD {
		m["client_id_metadata_document_supported"] = true
	}
	if s.IssParameter {
		m["authorization_response_iss_parameter_supported"] = true
	}
	if s.Revocation {
		m["revocation_endpoint"] = s.Issuer() + "/revoke"
	}
	if s.Registration {
		m["registration_endpoint"] = s.Issuer() + "/register"
	}
	jsonOut(w, 200, m)
}

// clientKnown checks the client of an authorization request; for a URL client_id (a client metadata document) it fetches the
// document, as an authorization server that supports them does, and checks it names the redirect address.
func (s *Server) clientKnown(id, redirect string) bool {
	if _, ok := s.clients[id]; ok {
		return true
	}
	if _, ok := s.Registry[id]; ok {
		return true
	}
	if strings.HasPrefix(id, "http") && s.CIMD {
		resp, err := http.Get(id)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var doc struct {
			ClientID     string   `json:"client_id"`
			RedirectURIs []string `json:"redirect_uris"`
			Method       string   `json:"token_endpoint_auth_method"`
		}
		if resp.StatusCode != 200 || json.Unmarshal(b, &doc) != nil || doc.ClientID != id || doc.Method != "none" {
			return false
		}
		for _, u := range doc.RedirectURIs {
			if u == redirect {
				return true
			}
		}
	}
	return false
}

// authorize consents by itself, as the user the X-Test-User header names (a real server would log them in).
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record(r)
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" || !s.clientKnown(q.Get("client_id"), redirect) {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	if s.RequireResource && q.Get("resource") == "" {
		http.Error(w, "no resource", http.StatusBadRequest)
		return
	}
	back, _ := url.Parse(redirect)
	out := back.Query()
	out.Set("state", q.Get("state"))
	iss := s.Issuer()
	switch {
	case s.WrongIss != "":
		iss = s.WrongIss
	case s.OmitIss == "true":
		iss = ""
	}
	if iss != "" && (s.IssParameter || s.WrongIss != "") {
		out.Set("iss", iss)
	}
	if s.AuthError != "" {
		out.Set("error", s.AuthError)
		out.Set("error_description", "secret detail the member must not see")
	} else {
		c := rnd(16)
		s.codes[c] = &code{client: q.Get("client_id"), redirect: redirect, challenge: q.Get("code_challenge"), resource: q.Get("resource"), scope: q.Get("scope"), user: r.Header.Get("X-Test-User")}
		out.Set("code", c)
	}
	back.RawQuery = out.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

// Consent plays the browser: it sends the authorization URL, as user, without following the redirect, and returns the
// parameters the authorization server redirects back with.
func Consent(authURL, user string) (url.Values, error) {
	req, _ := http.NewRequest(http.MethodGet, authURL, nil)
	req.Header.Set("X-Test-User", user)
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		return nil, fmt.Errorf("the authorization server answered HTTP %d", resp.StatusCode)
	}
	return loc.Query(), nil
}

// authenticated checks the client's authentication at the token or revocation endpoint and returns its id.
func (s *Server) authenticated(r *http.Request) (string, bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
	}
	if want, ok := s.clients[id]; ok {
		if s.Method == "client_secret_basic" && !basic || s.Method == "client_secret_post" && basic || secret != want {
			return "", false
		}
		return id, true
	}
	if want, ok := s.Registry[id]; ok {
		return id, secret == want
	}
	if strings.HasPrefix(id, "http") && secret == "" && !basic { // a client metadata document client: public
		return id, true
	}
	return "", false
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	_ = r.ParseForm()
	s.record(r)
	delay, status := s.TokenDelay, s.TokenError
	s.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	client, ok := s.authenticated(r)
	if !ok {
		jsonOut(w, 401, map[string]string{"error": "invalid_client", "error_description": "secret detail"})
		return
	}
	if s.RequireResource && r.Form.Get("resource") == "" {
		jsonOut(w, 400, map[string]string{"error": "invalid_target"})
		return
	}
	if e := map[string]string{"authorization_code": s.CodeError200, "refresh_token": s.RefreshError200}[r.Form.Get("grant_type")]; e != "" {
		jsonOut(w, 200, map[string]string{"error": e, "error_description": "secret detail"})
		return
	}
	var user, scope string
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		c := s.codes[r.Form.Get("code")]
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if c == nil || c.used || c.client != client || c.redirect != r.Form.Get("redirect_uri") || c.challenge != base64.RawURLEncoding.EncodeToString(sum[:]) || c.resource != r.Form.Get("resource") {
			if c != nil {
				c.used = true
			}
			jsonOut(w, 400, map[string]string{"error": "invalid_grant", "error_description": "secret detail"})
			return
		}
		c.used = true
		user, scope = c.user, c.scope
	case "refresh_token":
		rt := s.refresh[r.Form.Get("refresh_token")]
		if rt == nil || !rt.valid || s.InvalidGrant || rt.client != client {
			jsonOut(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		user, scope = rt.user, rt.scope
		if s.Rotate {
			rt.valid = false
		}
	default:
		jsonOut(w, 400, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	s.nextID++
	at := fmt.Sprintf("at-%d-%s", s.nextID, rnd(8))
	life := time.Duration(s.ExpiresIn) * time.Second
	if s.ExpiresIn < 0 {
		life = time.Hour // not said in the answer
	}
	s.Tokens[at] = &Token{User: user, Scope: scope, Expires: time.Now().Add(life)}
	tt := s.TokenType
	if tt == "" {
		tt = "Bearer"
	}
	resp := map[string]any{"access_token": at, "token_type": tt}
	if s.ExpiresIn >= 0 {
		resp["expires_in"] = s.ExpiresIn
	}
	if !s.OmitScope {
		resp["scope"] = scope
	}
	if !s.NoRefreshToken {
		newRT := r.Form.Get("refresh_token")
		if r.Form.Get("grant_type") == "authorization_code" || s.Rotate {
			newRT = fmt.Sprintf("rt-%d-%s", s.nextID, rnd(8))
			s.refresh[newRT] = &refresh{client: client, scope: scope, user: user, valid: true}
		}
		resp["refresh_token"] = newRT
	}
	jsonOut(w, 200, resp)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = r.ParseForm()
	s.record(r)
	if s.RevokeStatus != 0 {
		w.WriteHeader(s.RevokeStatus)
		return
	}
	if _, ok := s.authenticated(r); !ok {
		jsonOut(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	tok := r.Form.Get("token")
	if t := s.Tokens[tok]; t != nil {
		t.Revoked = true
	}
	if rt := s.refresh[tok]; rt != nil {
		rt.valid = false
	}
	w.WriteHeader(200)
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	s.reqs = append(s.reqs, Request{Path: r.URL.Path, Header: r.Header.Clone(), Form: url.Values{"body": {string(body)}}})
	var in struct {
		RedirectURIs []string `json:"redirect_uris"`
	}
	if json.Unmarshal(body, &in) != nil || len(in.RedirectURIs) == 0 {
		jsonOut(w, 400, map[string]string{"error": "invalid_client_metadata"})
		return
	}
	id, secret := "dcr-"+rnd(6), rnd(12)
	s.Registry[id] = secret
	jsonOut(w, 201, map[string]string{"client_id": id, "client_secret": secret, "token_endpoint_auth_method": "client_secret_post"})
}

// Secrets is every access token, refresh token, authorization code and client secret the double has issued or holds, for the
// tests that look for them where they must not be.
func (s *Server) Secrets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for t := range s.Tokens {
		out = append(out, t)
	}
	for t := range s.refresh {
		out = append(out, t)
	}
	for c := range s.codes {
		out = append(out, c)
	}
	for _, sec := range s.clients {
		out = append(out, sec)
	}
	for _, sec := range s.Registry {
		out = append(out, sec)
	}
	return out
}

// RefreshTokenOf returns a valid refresh token of user, or "".
func (s *Server) RefreshTokenOf(user string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for t, r := range s.refresh {
		if r.user == user && r.valid {
			return t
		}
	}
	return ""
}

// Count is how many requests of grant_type (or, for another path, of that path) were received.
func (s *Server) Count(path, grantType string) int {
	n := 0
	for _, r := range s.Requests(path) {
		if grantType == "" || r.Form.Get("grant_type") == grantType {
			n++
		}
	}
	return n
}
