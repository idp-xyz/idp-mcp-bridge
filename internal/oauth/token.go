package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Methods of client authentication at the token endpoint (RFC 6749 section 2.3, RFC 7591).
const (
	AuthNone  = "none"
	AuthBasic = "client_secret_basic"
	AuthPost  = "client_secret_post"
)

// ClientAuth is the client's identity and how it proves it.
type ClientAuth struct {
	ID     string
	Secret string
	Method string
}

// apply adds the client's identity to a token, revocation or registration-free request.
func (c ClientAuth) apply(form url.Values, h http.Header) {
	switch c.Method {
	case AuthBasic:
		// RFC 6749 section 2.3.1: the id and the secret are form-urlencoded before they are joined
		h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(c.ID)+":"+url.QueryEscape(c.Secret))))
	case AuthPost:
		form.Set("client_id", c.ID)
		form.Set("client_secret", c.Secret)
	default:
		form.Set("client_id", c.ID) // a public client says who it is
	}
}

// Tokens is a validated token response.
type Tokens struct {
	Access  string
	Refresh string
	// Scope is what the server says was granted; empty if the server omitted it (RFC 6749 section 5.1: then it is what was
	// requested, which the caller knows).
	Scope string
	// ExpiresIn in seconds; 0 if the server did not say.
	ExpiresIn int64
}

const maxToken = 16 << 10

// fixed set of the token endpoint's error codes the bridge distinguishes (RFC 6749 section 5.2); the error_description is
// never read into anything
var tokenErrors = map[string]bool{"invalid_request": true, "invalid_client": true, "invalid_grant": true, "unauthorized_client": true,
	"unsupported_grant_type": true, "invalid_scope": true,
	// GitHub's others, so that the log says what they were: none of them is a dead grant
	"incorrect_client_credentials": true, "redirect_uri_mismatch": true, "unverified_user_email": true}

// invalidGrantAliases are the codes of an authorization server that says "invalid_grant" in its own words: GitHub's, for a code that
// is wrong or used (`bad_verification_code`) and a refresh token that is expired or revoked (`bad_refresh_token`). A known deviation
// (ADR-0001 D36), kept to these two and explicit: a code that is not here is an error of the token endpoint, not a dead grant.
var invalidGrantAliases = map[string]string{"bad_verification_code": "invalid_grant", "bad_refresh_token": "invalid_grant"}

// TokenRequest posts a form to the token endpoint and validates the answer. A refusal by the server is an *Error whose Code
// is CodeInvalidGrant or CodeTokenEndpoint (its Detail the RFC 6749 error code, from the fixed set); no answer, a server
// error and 429 are Transient.
func (f *Fetcher) TokenRequest(ctx context.Context, endpoint string, ca ClientAuth, form url.Values) (Tokens, error) {
	h := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}, "Cache-Control": {"no-store"}}
	ca.apply(form, h)
	resp, err := f.Do(ctx, http.MethodPost, endpoint, h, []byte(form.Encode()))
	if err != nil {
		return Tokens{}, err
	}
	if resp.Status >= 500 || resp.Status == 429 {
		e := fail(CodeUnreachable, "the token endpoint answered HTTP %d", resp.Status)
		e.Transient = true
		return Tokens{}, e
	}
	// An error response is one whose body has an `error`, whatever the status: RFC 6749 section 5.2 says 400, GitHub answers 200
	// (ADR-0001 D36). Only the code is read, never error_description.
	var er struct {
		Error string `json:"error"`
	}
	if resp.Status != 200 || (json.Unmarshal(resp.Body, &er) == nil && er.Error != "") {
		_ = json.Unmarshal(resp.Body, &er)
		code := er.Error
		if mapped, ok := invalidGrantAliases[code]; ok {
			code = mapped
		}
		if !tokenErrors[code] {
			code = "unknown"
		}
		if code == "invalid_grant" {
			return Tokens{}, fail(CodeInvalidGrant, "")
		}
		return Tokens{}, fail(CodeTokenEndpoint, "%s (HTTP %d)", code, resp.Status)
	}
	var tr struct {
		AccessToken  string          `json:"access_token"`
		TokenType    string          `json:"token_type"`
		ExpiresIn    json.RawMessage `json:"expires_in"`
		RefreshToken string          `json:"refresh_token"`
		Scope        string          `json:"scope"`
	}
	if json.Unmarshal(resp.Body, &tr) != nil {
		return Tokens{}, fail(CodeTokenResponse, "not JSON")
	}
	// RFC 6749 section 5.1: token_type is required and is case-insensitive (RFC 6750: "Bearer"); a token of another type is
	// not one this bridge can present
	if !strings.EqualFold(tr.TokenType, "bearer") {
		return Tokens{}, fail(CodeTokenResponse, "token_type is not Bearer")
	}
	if tr.AccessToken == "" || len(tr.AccessToken) > maxToken || len(tr.RefreshToken) > maxToken || len(tr.Scope) > 4096 {
		return Tokens{}, fail(CodeTokenResponse, "no access token, or one that is too long")
	}
	out := Tokens{Access: tr.AccessToken, Refresh: tr.RefreshToken, Scope: tr.Scope}
	if raw := strings.Trim(string(tr.ExpiresIn), `" `); raw != "" && raw != "null" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			if fl, ferr := strconv.ParseFloat(raw, 64); ferr == nil && fl >= 0 {
				n, err = int64(fl), nil
			}
		}
		if err != nil {
			return Tokens{}, fail(CodeTokenResponse, "expires_in is not a number")
		}
		out.ExpiresIn = n
	}
	return out, nil
}

// Revoke asks the revocation endpoint to revoke a token (RFC 7009). The answer is checked only for success: 200 is, and so is
// an endpoint that says the token was not valid (RFC 7009 section 2.2).
func (f *Fetcher) Revoke(ctx context.Context, endpoint string, ca ClientAuth, token, hint string) error {
	form := url.Values{"token": {token}, "token_type_hint": {hint}}
	h := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Cache-Control": {"no-store"}}
	ca.apply(form, h)
	resp, err := f.Do(ctx, http.MethodPost, endpoint, h, []byte(form.Encode()))
	if err != nil {
		return err
	}
	if resp.Status != 200 {
		return fail(CodeTokenEndpoint, "the revocation endpoint answered HTTP %d", resp.Status)
	}
	return nil
}

// Registration is a dynamic client registration's answer (RFC 7591 section 3.2.1).
type Registration struct {
	ClientID   string
	Secret     string
	AuthMethod string
}

// Register registers a public client with the redirect address, as the operator opted in to (ADR-0001 D22).
func (f *Fetcher) Register(ctx context.Context, endpoint, name, redirect string) (Registration, error) {
	body, _ := json.Marshal(map[string]any{"client_name": name, "redirect_uris": []string{redirect}, "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "token_endpoint_auth_method": "none"})
	resp, err := f.Do(ctx, http.MethodPost, endpoint, http.Header{"Content-Type": {"application/json"}, "Accept": {"application/json"}}, body)
	if err != nil {
		return Registration{}, err
	}
	var r struct {
		ClientID   string `json:"client_id"`
		Secret     string `json:"client_secret"`
		AuthMethod string `json:"token_endpoint_auth_method"`
	}
	if (resp.Status != 200 && resp.Status != 201) || json.Unmarshal(resp.Body, &r) != nil || r.ClientID == "" || len(r.ClientID) > 1024 || len(r.Secret) > 4096 {
		return Registration{}, fail(CodeRegistrationFailed, "the registration endpoint answered HTTP %d", resp.Status)
	}
	m := r.AuthMethod
	switch {
	case m == "" && r.Secret != "":
		m = AuthBasic // RFC 7591 section 2: the default
	case m == "":
		m = AuthNone
	case m != AuthNone && m != AuthBasic && m != AuthPost:
		return Registration{}, fail(CodeRegistrationFailed, "the server assigned an authentication method this client does not do")
	}
	if m != AuthNone && r.Secret == "" {
		return Registration{}, fail(CodeRegistrationFailed, "a method that needs a secret and no secret")
	}
	return Registration{ClientID: r.ClientID, Secret: r.Secret, AuthMethod: m}, nil
}
