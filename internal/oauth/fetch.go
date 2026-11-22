// Package oauth is the bridge's OAuth 2.1 client for third-party MCP servers: discovery of the protected resource and of its
// authorization server (RFC 9728, RFC 8414, OpenID discovery), the client's identity (a client metadata document, a
// preregistered client, or, only if the operator opted in, a dynamic registration), the authorization code flow with PKCE
// and RFC 8707 resource binding, refresh, revocation, and the Service that ties them to the store (ADR-0001 D21 to D30).
//
// Written from the RFCs' rules, with the official Python SDK's client (mcp/client/auth) read for what an interoperable client
// does; where this client is stricter than the SDK, ADR-0001 section 3 says so.
package oauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"idp-mcp-bridge/internal/addr"
)

// Error is a failure the member and the operator can be told about by its code, never by what the third party said: the
// code is one of a fixed set, Detail is the bridge's own words for the log (it may name an address of the configuration or
// of the third party's metadata, never a token, code, verifier, state or secret).
type Error struct {
	Code   string
	Detail string
	// Transient: nothing is wrong with the request, the other side did not answer; the same call may work later.
	Transient bool
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

func fail(code, format string, args ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// Codes of Error.
const (
	CodeAddressRefused     = "address_refused"          // an address from the third party's metadata breaks the address rules
	CodeUnreachable        = "unreachable"              // no answer, or a server error
	CodeRedirectRefused    = "redirect_refused"         // a redirect to another origin, or one that would change the method
	CodeMetadataInvalid    = "metadata_invalid"         // a metadata document that is not one
	CodeResourceMismatch   = "resource_mismatch"        // the protected resource metadata names another resource
	CodeIssuerNotListed    = "issuer_not_listed"        // the pinned issuer is not among the resource's authorization servers
	CodeIssuerMismatch     = "issuer_mismatch"          // the authorization server metadata names another issuer
	CodePRMOrigin          = "resource_metadata_origin" // the challenge points the metadata at another origin
	CodePKCEUnsupported    = "pkce_unsupported"         // the server does not advertise S256
	CodeClientUnsupported  = "client_identity_unsupported"
	CodeTokenResponse      = "token_response_invalid"
	CodeInvalidGrant       = "invalid_grant"
	CodeTokenEndpoint      = "token_endpoint_error"
	CodeRegistrationFailed = "registration_failed"
)

// Fetcher makes the requests of the OAuth flow: through the checked dialer of internal/egress, to https addresses that pass
// the address rules (test origins excepted), with bodies bounded, following only redirects that stay on the origin and keep
// the method (the plan's section 1, item 7).
type Fetcher struct {
	HTTP        *http.Client // egress.NewClient: follows nothing itself
	TestOrigins map[string]bool
	MaxBody     int64 // default 256 KiB
}

const maxRedirects = 3

// Check applies the address rules to an address of the third party's metadata (or of the configuration): https, public, no
// userinfo, no fragment, port 443; a test origin may be anything. It returns the canonical address.
func (f *Fetcher) Check(raw string) (addr.Address, error) {
	a, err := addr.TargetWith(raw, addr.Options{TestOrigins: f.TestOrigins})
	if err != nil {
		return addr.Address{}, fail(CodeAddressRefused, "%s", strings.TrimPrefix(err.Error(), addr.ErrRefused.Error()+": "))
	}
	if a.Scheme != "https" && !a.Exempt {
		return addr.Address{}, fail(CodeAddressRefused, "%s is not an https address", redact(raw))
	}
	if strings.Contains(raw, "#") {
		return addr.Address{}, fail(CodeAddressRefused, "an address with a fragment")
	}
	return a, nil
}

// redact keeps scheme, host and path of an address, for a message.
func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid>"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// Response is what Do returns: the status, a few headers and the body (at most MaxBody bytes).
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// Do sends one request. A GET follows 301, 302, 303, 307 and 308 and a POST 307 and 308, to the same origin only, at most
// three times, the body sent again as it was; any other redirect is CodeRedirectRefused. A body over the limit is an error.
func (f *Fetcher) Do(ctx context.Context, method, raw string, header http.Header, body []byte) (*Response, error) {
	if _, err := f.Check(raw); err != nil {
		return nil, err
	}
	max := f.MaxBody
	if max <= 0 {
		max = 256 << 10
	}
	cur := raw
	for hop := 0; ; hop++ {
		req, err := http.NewRequestWithContext(ctx, method, cur, bytes.NewReader(body))
		if err != nil {
			return nil, fail(CodeAddressRefused, "not an address")
		}
		for k, v := range header {
			req.Header[k] = v
		}
		req.Header.Set("User-Agent", "idp-mcp-bridge")
		resp, err := f.HTTP.Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			if errors.Is(err, addr.ErrNotPublic) {
				return nil, fail(CodeAddressRefused, "the address resolves to a non-public address")
			}
			e := fail(CodeUnreachable, "%s: %v", redact(cur), err)
			e.Transient = true
			return nil, e
		}
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, max+1))
		resp.Body.Close()
		if rerr != nil {
			e := fail(CodeUnreachable, "the answer could not be read")
			e.Transient = true
			return nil, e
		}
		if int64(len(data)) > max {
			return nil, fail(CodeMetadataInvalid, "an answer longer than %d bytes", max)
		}
		switch resp.StatusCode {
		case 301, 302, 303, 307, 308:
			keeps := resp.StatusCode == 307 || resp.StatusCode == 308 || method == http.MethodGet
			from, _ := url.Parse(cur)
			to, err := from.Parse(resp.Header.Get("Location"))
			if !keeps || err != nil || !sameOrigin(from, to) || hop >= maxRedirects {
				return nil, fail(CodeRedirectRefused, "from %s", redact(cur))
			}
			if _, err := f.Check(to.String()); err != nil {
				return nil, err
			}
			cur = to.String()
			continue
		}
		return &Response{Status: resp.StatusCode, Header: resp.Header, Body: data}, nil
	}
}
