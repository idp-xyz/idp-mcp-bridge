package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"idp-mcp-bridge/internal/config"
)

// ASMeta is what the bridge uses of the authorization server's metadata (RFC 8414 section 2).
type ASMeta struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RevocationEndpoint    string   `json:"revocation_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypes            []string `json:"grant_types_supported"`
	ScopesSupported       []string `json:"scopes_supported"`
	CIMD                  bool     `json:"client_id_metadata_document_supported"`
	IssParameter          bool     `json:"authorization_response_iss_parameter_supported"`
}

// Discovered is the outcome of discovery for a connection: the authorization server, as vouched for by the resource.
type Discovered struct {
	AS ASMeta
	// PRMScopes are the scopes the protected resource says it supports, the fallback when the connection lists none.
	PRMScopes []string
}

type prm struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// DiscoveryTTL is how long a successful discovery is reused.
const DiscoveryTTL = time.Hour

// Discoverer finds and checks the authorization server of a connection, and keeps what it found for DiscoveryTTL. Nothing
// is kept of a failure, and Drop forgets a success the caller has reason to doubt (the token endpoint did not answer).
type Discoverer struct {
	F   *Fetcher
	TTL time.Duration
	Now func() time.Time
	// Probe, if set, is asked for the WWW-Authenticate header of an unauthenticated request to the connection, on a cache
	// miss: the resource_metadata of its challenge is where RFC 9728 says to look first (ADR-0001 D21).
	Probe func(ctx context.Context, connection string) string

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	d     *Discovered
	until time.Time
}

func (d *Discoverer) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Drop forgets what is known of a connection.
func (d *Discoverer) Drop(connection string) {
	d.mu.Lock()
	delete(d.cache, connection)
	d.mu.Unlock()
}

// Get returns the discovery of a connection, from the cache or from the network.
func (d *Discoverer) Get(ctx context.Context, c config.Connection) (*Discovered, error) {
	issuer := c.Authorization.Issuer
	d.mu.Lock()
	if e, ok := d.cache[c.ID]; ok && d.now().Before(e.until) && e.d.AS.Issuer == issuer {
		d.mu.Unlock()
		return e.d, nil
	}
	d.mu.Unlock()
	challenge := ""
	if d.Probe != nil {
		challenge = d.Probe(ctx, c.ID)
	}
	got, err := d.discover(ctx, c, challenge)
	if err != nil {
		return nil, err
	}
	ttl := d.TTL
	if ttl == 0 {
		ttl = DiscoveryTTL
	}
	d.mu.Lock()
	if d.cache == nil {
		d.cache = map[string]cached{}
	}
	d.cache[c.ID] = cached{got, d.now().Add(ttl)}
	d.mu.Unlock()
	return got, nil
}

func (d *Discoverer) getJSON(ctx context.Context, raw string, into any) (status int, ok bool, err error) {
	resp, err := d.F.Do(ctx, http.MethodGet, raw, http.Header{"Accept": {"application/json"}}, nil)
	if err != nil {
		return 0, false, err
	}
	if resp.Status >= 500 {
		e := fail(CodeUnreachable, "%s answered HTTP %d", redact(raw), resp.Status)
		e.Transient = true
		return resp.Status, false, e
	}
	if resp.Status != 200 {
		return resp.Status, false, nil
	}
	if json.Unmarshal(resp.Body, into) != nil {
		return 200, false, nil
	}
	return 200, true, nil
}

func (d *Discoverer) discover(ctx context.Context, c config.Connection, wwwAuth string) (*Discovered, error) {
	endpoint := c.Parsed
	canonical := endpoint.URL()

	// 1. the protected resource metadata (RFC 9728): the challenge's resource_metadata, else the well-known paths
	var urls []string
	if ch := ParseChallenge(wwwAuth); ch["resource_metadata"] != "" {
		u, err := url.Parse(ch["resource_metadata"])
		if err != nil || !strings.EqualFold(u.Scheme, endpoint.Scheme) || !strings.EqualFold(u.Host, hostPort(endpoint.Host, endpoint.Port, endpoint.Scheme)) {
			// A challenge that points the metadata at another origin is not followed: what the connection's authorization
			// server is, is decided by the resource's own origin (and the pinned issuer), not by a header
			return nil, fail(CodePRMOrigin, "the challenge's resource_metadata is not on the connection's origin")
		}
		urls = append(urls, ch["resource_metadata"])
	}
	origin := endpoint.Scheme + "://" + hostPort(endpoint.Host, endpoint.Port, endpoint.Scheme)
	if p := strings.SplitN(endpoint.Path, "?", 2)[0]; p != "" && p != "/" {
		urls = append(urls, origin+"/.well-known/oauth-protected-resource"+p)
	}
	urls = append(urls, origin+"/.well-known/oauth-protected-resource")

	var res prm
	found := false
	for _, u := range urls {
		var m prm
		_, ok, err := d.getJSON(ctx, u, &m)
		if err != nil {
			return nil, err
		}
		if ok {
			res, found = m, true
			break
		}
	}
	if !found {
		return nil, fail(CodeMetadataInvalid, "no protected resource metadata for the connection (RFC 9728)")
	}
	got, err := d.F.Check(res.Resource)
	if err != nil || got.URL() != canonical {
		return nil, fail(CodeResourceMismatch, "the protected resource metadata names %s, the connection's endpoint is %s", redact(res.Resource), redact(canonical))
	}
	if !slices.Contains(res.AuthorizationServers, c.Authorization.Issuer) {
		return nil, fail(CodeIssuerNotListed, "the pinned issuer is not among the resource's authorization servers")
	}

	// 2. the authorization server metadata (RFC 8414), then OpenID discovery
	as, err := d.asMetadata(ctx, c.Authorization.Issuer)
	if err != nil {
		return nil, err
	}
	return &Discovered{AS: *as, PRMScopes: res.ScopesSupported}, nil
}

func portSuffix(port int, scheme string) string {
	if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
		return ""
	}
	return ":" + itoa(port)
}

func hostPort(host string, port int, scheme string) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + portSuffix(port, scheme)
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// MetadataURLs are the places RFC 8414 section 3 and OpenID Connect Discovery put the metadata of an issuer, in the order
// to try them: OAuth then OpenID, the well-known path inserted before the issuer's path, then (OpenID) appended after it.
func MetadataURLs(issuer string) []string {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil
	}
	origin := u.Scheme + "://" + u.Host
	path := strings.TrimRight(u.Path, "/")
	if path == "" {
		return []string{origin + "/.well-known/oauth-authorization-server", origin + "/.well-known/openid-configuration"}
	}
	return []string{origin + "/.well-known/oauth-authorization-server" + path, origin + "/.well-known/openid-configuration" + path, origin + path + "/.well-known/openid-configuration"}
}

func (d *Discoverer) asMetadata(ctx context.Context, issuer string) (*ASMeta, error) {
	for _, u := range MetadataURLs(issuer) {
		var m ASMeta
		_, ok, err := d.getJSON(ctx, u, &m)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue // not served here, or not metadata: the next place
		}
		// Simple string comparison, character for character (RFC 8414 section 3.3): the document at a pinned issuer's address
		// that names another issuer is not that issuer's, and is not followed to wherever it points.
		if m.Issuer != issuer {
			return nil, fail(CodeIssuerMismatch, "the metadata names issuer %s, the connection pins %s", redact(m.Issuer), redact(issuer))
		}
		for _, e := range []struct{ name, v string }{{"authorization_endpoint", m.AuthorizationEndpoint}, {"token_endpoint", m.TokenEndpoint}} {
			if e.v == "" {
				return nil, fail(CodeMetadataInvalid, "no %s", e.name)
			}
		}
		for _, v := range []string{m.AuthorizationEndpoint, m.TokenEndpoint, m.RevocationEndpoint, m.RegistrationEndpoint} {
			if v == "" {
				continue
			}
			if _, err := d.F.Check(v); err != nil {
				return nil, err
			}
		}
		// MCP requires a client to refuse an authorization server that does not advertise PKCE with S256; the official SDK
		// does not check (ADR-0001 section 3)
		if !slices.Contains(m.CodeChallengeMethods, "S256") {
			return nil, fail(CodePKCEUnsupported, "the metadata does not list S256 in code_challenge_methods_supported")
		}
		if len(m.GrantTypes) > 0 && !slices.Contains(m.GrantTypes, "authorization_code") {
			return nil, fail(CodeMetadataInvalid, "authorization_code is not a supported grant type")
		}
		return &m, nil
	}
	return nil, fail(CodeMetadataInvalid, "no authorization server metadata for the pinned issuer")
}
