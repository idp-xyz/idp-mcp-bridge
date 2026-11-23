// Package config reads the connections file: the list of third-party MCP services the bridge fronts (ADR-0001 D3,
// D4). The file is read once at start and validated strictly: an unknown key, a missing required one, an address that
// breaks the address rules or a setting out of its bounds is an error that stops the bridge, never a default that
// would be guessed. B2 reads the same file; what it needs (the pinned issuer, the client identity, the scopes) is
// required and checked now, so that the file an operator writes today does not change shape when OAuth arrives.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"idp-mcp-bridge/internal/addr"
)

// Authorization modes of a connection.
const (
	// AuthNone: the third party needs no token. Every member's call goes out without one, and nothing is asked of
	// the token source for it.
	AuthNone = "none"
	// AuthOAuth: each member authorizes once and the bridge calls with that member's own token (B2).
	AuthOAuth = "oauth"
)

// RevocationGitHub is Authorization.Revocation for GitHub's own revocation API.
const RevocationGitHub = "github"

// Client identity modes (idp-mcp-bridge-oauth-plan.md section 1, item 2).
const (
	// ClientCIMD: the client_id is an https address of a client metadata document the bridge's operator hosts.
	ClientCIMD = "cimd"
	// ClientPreregistered: a client registered at the third party beforehand: its id, and a file holding its secret.
	ClientPreregistered = "preregistered"
)

// Defaults and bounds of the limits and the breaker (ADR-0001 D12, D13).
const (
	DefaultWindow          = 60 * time.Second
	DefaultConnectionCalls = 300
	DefaultMemberCalls     = 60
	DefaultBreakerFailures = 5
	DefaultBreakerOpen     = 30 * time.Second

	maxCalls              = 100000
	maxWindowSeconds      = 3600
	maxBreakerFailures    = 100
	maxBreakerOpenSeconds = 3600
	maxTitle              = 100
	maxScopes             = 50
	maxScope              = 128
	maxConnections        = 200
	maxFile               = 1 << 20
	maxPath               = 1024
	maxClientID           = 256
)

var idRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$`)

// File is the YAML document.
type File struct {
	Connections []Connection `yaml:"connections"`
}

// Connection is one third-party service, as written in the file.
type Connection struct {
	// ID is the connection's name everywhere: the path of its endpoint (/mcp/<id>), the server name the gateway
	// registers, the key of a member's grant. Lower case letters, digits and hyphens, at most 40.
	ID    string `yaml:"id"`
	Title string `yaml:"title"`
	// Endpoint is the third party's MCP endpoint: https, public, no query.
	Endpoint      string        `yaml:"endpoint"`
	Authorization Authorization `yaml:"authorization"`
	RateLimit     RateLimit     `yaml:"rateLimit"`
	Breaker       Breaker       `yaml:"breaker"`

	// Parsed is the endpoint as addr read it (not from the file).
	Parsed addr.Address `yaml:"-"`
}

// Authorization says what credential the third party wants.
type Authorization struct {
	Mode string `yaml:"mode"`
	// Issuer is the authorization server's issuer, pinned: B2 refuses a discovery document that names another
	// (plan section 3). Required for oauth, refused for none.
	Issuer string `yaml:"issuer"`
	Client Client `yaml:"client"`
	// Scopes are requested as written, in order. B2 asks for more only when the third party says so.
	Scopes []string `yaml:"scopes"`
	// ReviewerScopes are what the connection's reviewer account is authorized for: the least that lets it list the tools
	// (ADR-0001 D33). If empty, Scopes.
	ReviewerScopes []string `yaml:"reviewerScopes"`
	// ScopesFromResource is the explicit opt-in to ask, when Scopes is empty, for every scope the protected resource lists in its
	// metadata (the MCP specification's SHOULD). Off by default: an operator who lists no scopes gets none requested, never everything
	// the third party offers (ADR-0001 D37).
	ScopesFromResource bool `yaml:"scopesFromResource"`
	// Revocation says how the member's tokens are revoked at the third party: "" is RFC 7009 at the server's revocation endpoint, if
	// it has one; "github" is GitHub's application grant API with the preregistered client's id and secret (ADR-0001 D42).
	Revocation string `yaml:"revocation"`
}

// Client is the bridge's identity at the authorization server.
type Client struct {
	Mode string `yaml:"mode"`
	// Document is the CIMD address (cimd): it is the client_id.
	Document string `yaml:"document"`
	// ID and SecretFile name a client registered beforehand (preregistered). The file holds the secret; it is
	// a mounted Secret, never the secret in this file.
	ID         string `yaml:"id"`
	SecretFile string `yaml:"secretFile"`
	// DynamicRegistration lets B2 register a client at the authorization server on the fly when the server does not
	// accept a CIMD address. Off unless written: the revision deprecates it, and it is the last resort (plan section 6).
	DynamicRegistration bool `yaml:"dynamicRegistration"`
}

// RateLimit is a sliding window, in memory, per replica (as idp-web ADR-0001 D22).
type RateLimit struct {
	WindowSeconds int `yaml:"windowSeconds"`
	// ConnectionCalls bounds all members together; MemberCalls one member on this connection.
	ConnectionCalls int `yaml:"connectionCalls"`
	MemberCalls     int `yaml:"memberCalls"`
}

// Breaker opens after Failures consecutive failures, stays open for OpenSeconds and then lets one call through.
type Breaker struct {
	Failures    int `yaml:"failures"`
	OpenSeconds int `yaml:"openSeconds"`
}

// Window is the rate-limit window.
func (r RateLimit) Window() time.Duration { return time.Duration(r.WindowSeconds) * time.Second }

// Open is how long the breaker stays open.
func (b Breaker) Open() time.Duration { return time.Duration(b.OpenSeconds) * time.Second }

// Options of Parse and Load.
type Options struct {
	// TestOrigins are exact host:port pairs exempt from the address rules and allowed to be plain http, for
	// acceptance only (IDP_BRIDGE_TEST_ORIGINS, ADR-0001 D6). Nothing else is exempted by them.
	TestOrigins map[string]bool
}

// Parse reads and validates the connections file. The errors name the connection and the key.
func Parse(data []byte, o Options) ([]Connection, error) {
	if len(data) > maxFile {
		return nil, errors.New("the file is longer than 1 MiB")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the file is empty")
		}
		return nil, fmt.Errorf("not valid: %w", err)
	}
	if err := dec.Decode(&yaml.Node{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("the file holds more than one YAML document")
	}
	if len(f.Connections) == 0 {
		return nil, errors.New("no connections: a bridge with none has nothing to serve")
	}
	if len(f.Connections) > maxConnections {
		return nil, fmt.Errorf("more than %d connections", maxConnections)
	}
	seen := map[string]bool{}
	for i := range f.Connections {
		c := &f.Connections[i]
		if err := c.validate(o); err != nil {
			if c.ID != "" {
				return nil, fmt.Errorf("connection %q: %w", c.ID, err)
			}
			return nil, fmt.Errorf("connection %d: %w", i+1, err)
		}
		if seen[c.ID] {
			return nil, fmt.Errorf("connection %q is listed twice", c.ID)
		}
		seen[c.ID] = true
	}
	return f.Connections, nil
}

// Load reads the file, validates it and checks that the secret files it names can be read.
func Load(path string, o Options) ([]Connection, error) {
	if path == "" {
		return nil, errors.New("no connections file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cs, err := Parse(b, o)
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		if f := c.Authorization.Client.SecretFile; f != "" {
			s, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("connection %q: client.secretFile: %w", c.ID, err)
			}
			if strings.TrimSpace(string(s)) == "" {
				return nil, fmt.Errorf("connection %q: client.secretFile: the file is empty", c.ID)
			}
		}
	}
	return cs, nil
}

func (c *Connection) validate(o Options) error {
	if !idRE.MatchString(c.ID) {
		return errors.New("id must be lower case letters, digits and hyphens, starting and ending with a letter or digit, at most 40 characters")
	}
	if c.Title == "" || len(c.Title) > maxTitle || strings.ContainsFunc(c.Title, func(r rune) bool { return unicode.IsControl(r) }) {
		return errors.New("title is required, at most 100 bytes, without control characters")
	}
	a, err := publicHTTPS("endpoint", c.Endpoint, o, false)
	if err != nil {
		return err
	}
	c.Parsed = a
	if err := c.Authorization.validate(o); err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	if err := c.RateLimit.validate(); err != nil {
		return fmt.Errorf("rateLimit: %w", err)
	}
	if err := c.Breaker.validate(); err != nil {
		return fmt.Errorf("breaker: %w", err)
	}
	return nil
}

// publicHTTPS applies the address rules of internal/addr (the rules of idp-web, ADR-0001 D6) and the rule of this file
// on top: https, except for a test origin; no userinfo (addr), no fragment, and no query unless allowed. A query on the
// endpoint is refused because it is where a key would be put, in a file that is a ConfigMap and not a Secret.
func publicHTTPS(key, raw string, o Options, query bool) (addr.Address, error) {
	a, err := addr.TargetWith(raw, addr.Options{TestOrigins: o.TestOrigins})
	if err != nil {
		return addr.Address{}, fmt.Errorf("%s: %w", key, err)
	}
	u, _ := url.Parse(raw) // addr has parsed it
	if a.Scheme != "https" && !a.Exempt {
		return addr.Address{}, fmt.Errorf("%s: only https addresses are accepted (the third party's credentials travel to it)", key)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return addr.Address{}, fmt.Errorf("%s: an address with a fragment is not accepted", key)
	}
	if !query && (u.RawQuery != "" || u.ForceQuery) {
		return addr.Address{}, fmt.Errorf("%s: an address with a query is not accepted; a key does not belong in this file", key)
	}
	return a, nil
}

func (a *Authorization) validate(o Options) error {
	switch a.Mode {
	case AuthNone:
		if a.Issuer != "" || a.Client != (Client{}) || len(a.Scopes) > 0 || len(a.ReviewerScopes) > 0 || a.ScopesFromResource || a.Revocation != "" {
			return errors.New("mode none takes no issuer, client or scopes: they would be ignored, and an ignored line is a wrong belief")
		}
		return nil
	case AuthOAuth:
	case "":
		return errors.New("mode is required: none or oauth")
	default:
		return fmt.Errorf("mode %q is not none or oauth", a.Mode)
	}
	if a.Issuer == "" {
		return errors.New("issuer is required for oauth: the authorization server is pinned, not discovered")
	}
	// An issuer is an https address with no query and no fragment (RFC 8414); a path is allowed.
	if _, err := publicHTTPS("issuer", a.Issuer, o, false); err != nil {
		return err
	}
	if err := a.Client.validate(o); err != nil {
		return fmt.Errorf("client: %w", err)
	}
	switch a.Revocation {
	case "":
	case RevocationGitHub:
		if a.Client.Mode != ClientPreregistered {
			return errors.New("revocation: github needs a preregistered client: the application's id and secret are what GitHub's API authenticates")
		}
	default:
		return fmt.Errorf("revocation %q is not github (or omitted)", a.Revocation)
	}
	for _, list := range []struct {
		key    string
		scopes []string
	}{{"scopes", a.Scopes}, {"reviewerScopes", a.ReviewerScopes}} {
		if len(list.scopes) > maxScopes {
			return fmt.Errorf("more than %d %s", maxScopes, list.key)
		}
		seen := map[string]bool{}
		for _, s := range list.scopes {
			// RFC 6749 section 3.3: printable ASCII without space, double quote and backslash
			if s == "" || len(s) > maxScope || strings.ContainsFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e || r == '"' || r == '\\' }) {
				return fmt.Errorf("%s: %q is not a valid scope token", list.key, s)
			}
			if seen[s] {
				return fmt.Errorf("%s: scope %q is listed twice", list.key, s)
			}
			seen[s] = true
		}
	}
	return nil
}

func (c *Client) validate(o Options) error {
	switch c.Mode {
	case ClientCIMD:
		if c.ID != "" || c.SecretFile != "" {
			return errors.New("mode cimd takes a document, not an id or a secretFile")
		}
		if len(c.Document) > addr.MaxURL {
			return errors.New("document is too long")
		}
		a, err := publicHTTPS("document", c.Document, o, false)
		if err != nil {
			return err
		}
		if a.Path == "/" {
			return errors.New("document: the client_id must have a path (client metadata documents are not at the root)")
		}
	case ClientPreregistered:
		if c.Document != "" {
			return errors.New("mode preregistered takes an id and a secretFile, not a document")
		}
		if c.DynamicRegistration {
			return errors.New("dynamicRegistration has no meaning for a preregistered client")
		}
		if c.ID == "" || len(c.ID) > maxClientID || strings.ContainsFunc(c.ID, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
			return errors.New("id is required: printable ASCII without spaces, at most 256 bytes")
		}
		if c.SecretFile == "" || len(c.SecretFile) > maxPath || !filepath.IsAbs(c.SecretFile) {
			return errors.New("secretFile is required and must be an absolute path (a mounted Secret): the secret itself does not belong in this file")
		}
	case "":
		return errors.New("mode is required: cimd or preregistered")
	default:
		return fmt.Errorf("mode %q is not cimd or preregistered", c.Mode)
	}
	return nil
}

func (r *RateLimit) validate() error {
	def := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	def(&r.WindowSeconds, int(DefaultWindow/time.Second))
	def(&r.ConnectionCalls, DefaultConnectionCalls)
	def(&r.MemberCalls, DefaultMemberCalls)
	switch {
	case r.WindowSeconds < 1 || r.WindowSeconds > maxWindowSeconds:
		return fmt.Errorf("windowSeconds must be 1 to %d", maxWindowSeconds)
	case r.ConnectionCalls < 1 || r.ConnectionCalls > maxCalls:
		return fmt.Errorf("connectionCalls must be 1 to %d", maxCalls)
	case r.MemberCalls < 1 || r.MemberCalls > maxCalls:
		return fmt.Errorf("memberCalls must be 1 to %d", maxCalls)
	}
	return nil
}

func (b *Breaker) validate() error {
	if b.Failures == 0 {
		b.Failures = DefaultBreakerFailures
	}
	if b.OpenSeconds == 0 {
		b.OpenSeconds = int(DefaultBreakerOpen / time.Second)
	}
	switch {
	case b.Failures < 1 || b.Failures > maxBreakerFailures:
		return fmt.Errorf("failures must be 1 to %d", maxBreakerFailures)
	case b.OpenSeconds < 1 || b.OpenSeconds > maxBreakerOpenSeconds:
		return fmt.Errorf("openSeconds must be 1 to %d", maxBreakerOpenSeconds)
	}
	return nil
}
