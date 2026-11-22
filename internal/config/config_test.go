package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const good = `
connections:
  - id: github
    title: GitHub
    endpoint: https://mcp.github.example.com/mcp
    authorization:
      mode: oauth
      issuer: https://auth.github.example.com
      client: {mode: cimd, document: "https://workspace.example.com/.well-known/mcp-client/github.json"}
      scopes: [repo, read:org]
    rateLimit: {windowSeconds: 30, connectionCalls: 100, memberCalls: 10}
    breaker: {failures: 3, openSeconds: 10}
  - id: docs
    title: Public docs
    endpoint: https://docs.example.com/mcp
    authorization: {mode: none}
  - id: crm
    title: CRM
    endpoint: https://crm.example.com/mcp
    authorization:
      mode: oauth
      issuer: https://crm.example.com/auth/realms/main
      client: {mode: preregistered, id: bridge-1, secretFile: /etc/idp/secrets/crm-secret}
`

func TestAValidFileIsReadWithItsDefaults(t *testing.T) {
	cs, err := Parse([]byte(good), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 3 || cs[0].ID != "github" || cs[0].Parsed.Host != "mcp.github.example.com" || cs[0].Parsed.URL() != "https://mcp.github.example.com/mcp" {
		t.Fatalf("%+v", cs)
	}
	if cs[0].RateLimit.MemberCalls != 10 || cs[0].RateLimit.Window() != 30*time.Second || cs[0].Breaker.Failures != 3 || cs[0].Breaker.Open() != 10*time.Second {
		t.Fatalf("%+v", cs[0])
	}
	// the defaults, with nothing written
	d := cs[1]
	if d.RateLimit.Window() != DefaultWindow || d.RateLimit.ConnectionCalls != DefaultConnectionCalls || d.RateLimit.MemberCalls != DefaultMemberCalls ||
		d.Breaker.Failures != DefaultBreakerFailures || d.Breaker.Open() != DefaultBreakerOpen {
		t.Fatalf("%+v", d)
	}
	// dynamic registration is off unless written
	if cs[0].Authorization.Client.DynamicRegistration || cs[2].Authorization.Client.DynamicRegistration {
		t.Fatal("dynamic registration is on by default")
	}
}

// one change to the good file at a time, each of which must be refused, and why
func TestEachInvalidSettingIsRefusedForItsOwnReason(t *testing.T) {
	cases := []struct{ name, from, to, want string }{
		{"an unknown key", "title: GitHub", "title: GitHub\n    colour: red", "colour"},
		{"an uppercase id", "id: github", "id: GitHub", "id must be"},
		{"an id with a slash", "id: github", "id: a/b", "id must be"},
		{"an id that is too long", "id: github", "id: " + strings.Repeat("a", 41), "id must be"},
		{"no title", "    title: GitHub\n", "", "title is required"},
		{"a title with a control character", "title: GitHub", `title: "Git\nHub"`, "title is required"},
		{"a duplicate id", "id: docs", "id: github", "listed twice"},
		{"a plain http endpoint", "endpoint: https://mcp.github.example.com/mcp", "endpoint: http://mcp.github.example.com/mcp", "only https"},
		{"a loopback endpoint", "endpoint: https://mcp.github.example.com/mcp", "endpoint: https://127.0.0.1/mcp", "not a public address"},
		{"a private endpoint", "endpoint: https://mcp.github.example.com/mcp", "endpoint: https://10.1.2.3/mcp", "not a public address"},
		{"the metadata address", "endpoint: https://mcp.github.example.com/mcp", "endpoint: https://169.254.169.254/mcp", "not a public address"},
		{"an IPv6 loopback", "endpoint: https://mcp.github.example.com/mcp", "endpoint: https://[::1]/mcp", "not a public address"},
		{"a hex IP", "endpoint: https://mcp.github.example.com/mcp", "endpoint: https://0x7f.1/mcp", "IP address"},
		{"another port", "endpoint: https://mcp.github.example.com/mcp", "endpoint: https://mcp.github.example.com:8443/mcp", "port 8443"},
		{"userinfo", "endpoint: https://mcp.github.example.com/mcp", "endpoint: https://u:p@mcp.github.example.com/mcp", "user name"},
		{"a query in the endpoint", "endpoint: https://mcp.github.example.com/mcp", "endpoint: https://mcp.github.example.com/mcp?key=1", "query"},
		{"a fragment in the endpoint", "endpoint: https://mcp.github.example.com/mcp", "endpoint: https://mcp.github.example.com/mcp#x", "fragment"},
		{"no authorization mode", "mode: oauth\n      issuer: https://auth.github.example.com", "issuer: https://auth.github.example.com", "mode is required"},
		{"an unknown authorization mode", "mode: oauth\n      issuer: https://auth.github.example.com", "mode: basic\n      issuer: https://auth.github.example.com", "not none or oauth"},
		{"oauth without an issuer", "      issuer: https://auth.github.example.com\n", "", "issuer is required"},
		{"a private issuer", "issuer: https://auth.github.example.com", "issuer: https://192.168.0.9", "not a public address"},
		{"an http issuer", "issuer: https://auth.github.example.com", "issuer: http://auth.github.example.com", "only https"},
		{"an issuer with a query", "issuer: https://auth.github.example.com", "issuer: https://auth.github.example.com/?a=1", "query"},
		{"no client", "      client: {mode: cimd, document: \"https://workspace.example.com/.well-known/mcp-client/github.json\"}\n", "", "client: mode is required"},
		{"an unknown client mode", "client: {mode: cimd,", "client: {mode: magic,", "not cimd or preregistered"},
		{"a cimd document at the root", "https://workspace.example.com/.well-known/mcp-client/github.json", "https://workspace.example.com/", "must have a path"},
		{"a cimd document that is not https", "https://workspace.example.com/.well-known", "http://workspace.example.com/.well-known", "only https"},
		{"a cimd client with an id", "client: {mode: cimd,", "client: {mode: cimd, id: x,", "takes a document"},
		{"a negative member limit", "memberCalls: 10", "memberCalls: -1", "memberCalls must be"},
		{"a huge window", "windowSeconds: 30", "windowSeconds: 999999", "windowSeconds must be"},
		{"too many breaker failures", "failures: 3", "failures: 1000", "failures must be"},
		{"a duplicate scope", "scopes: [repo, read:org]", "scopes: [repo, repo]", "listed twice"},
		{"a scope with a space", "scopes: [repo, read:org]", `scopes: ["repo read"]`, "not a valid scope"},
		{"an unknown key in a nested block", "memberCalls: 10", "memberCalls: 10, burst: 5", "burst"},
	}
	for _, c := range cases {
		if !strings.Contains(good, c.from) {
			t.Fatalf("%s: the file has no %q", c.name, c.from)
		}
		_, err := Parse([]byte(strings.Replace(good, c.from, c.to, 1)), Options{})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error containing %q", c.name, err, c.want)
		}
	}
}

func TestSettingsThatDoNotFitTheirModeAreRefused(t *testing.T) {
	for name, y := range map[string]string{
		"none with an issuer":                             `connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: none, issuer: "https://a.example.com"}}]`,
		"none with scopes":                                `connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: none, scopes: [x]}}]`,
		"none with a client":                              `connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: none, client: {mode: cimd}}}]`,
		"preregistered without an id":                     `connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: oauth, issuer: "https://a.example.com", client: {mode: preregistered, secretFile: /s}}}]`,
		"preregistered without a secret file":             `connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: oauth, issuer: "https://a.example.com", client: {mode: preregistered, id: x}}}]`,
		"a relative secret file":                          `connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: oauth, issuer: "https://a.example.com", client: {mode: preregistered, id: x, secretFile: secret}}}]`,
		"preregistered with a document":                   `connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: oauth, issuer: "https://a.example.com", client: {mode: preregistered, id: x, secretFile: /s, document: "https://a.example.com/c"}}}]`,
		"dynamic registration for a preregistered client": `connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: oauth, issuer: "https://a.example.com", client: {mode: preregistered, id: x, secretFile: /s, dynamicRegistration: true}}}]`,
	} {
		if _, err := Parse([]byte(y), Options{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDynamicRegistrationIsAnExplicitOptInOfACimdClient(t *testing.T) {
	y := `connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: oauth, issuer: "https://a.example.com", client: {mode: cimd, document: "https://w.example.com/c.json", dynamicRegistration: true}}}]`
	cs, err := Parse([]byte(y), Options{})
	if err != nil || !cs[0].Authorization.Client.DynamicRegistration {
		t.Fatalf("%v", err)
	}
}

func TestAFileThatIsEmptyOrHasNoConnectionsOrTwoDocumentsIsRefused(t *testing.T) {
	for name, y := range map[string]string{"empty": "", "no connections": "connections: []", "another top-level key": "connections: []\nextra: 1",
		"two documents": "connections: [{id: a, title: A, endpoint: \"https://a.example.com/mcp\", authorization: {mode: none}}]\n---\nconnections: []", "not yaml": "connections: [", "a list": "- a"} {
		if _, err := Parse([]byte(y), Options{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestATestOriginIsExemptFromHTTPSAndTheAddressRulesAndNothingElseIs(t *testing.T) {
	y := func(endpoint string) string {
		return `connections: [{id: a, title: A, endpoint: "` + endpoint + `", authorization: {mode: none}}]`
	}
	o := Options{TestOrigins: map[string]bool{"127.0.0.1:9999": true}}
	if cs, err := Parse([]byte(y("http://127.0.0.1:9999/mcp")), o); err != nil || cs[0].Parsed.URL() != "http://127.0.0.1:9999/mcp" {
		t.Fatalf("the test origin: %v", err)
	}
	for _, e := range []string{"http://127.0.0.1:9998/mcp", "http://127.0.0.2:9999/mcp", "https://127.0.0.1/mcp", "http://localhost:9999/mcp"} {
		if _, err := Parse([]byte(y(e)), o); err == nil {
			t.Errorf("%s: accepted", e)
		}
	}
	// without the exemption the same address is refused
	if _, err := Parse([]byte(y("http://127.0.0.1:9999/mcp")), Options{}); err == nil {
		t.Error("accepted without the exemption")
	}
}

func TestLoadChecksThatTheSecretFileCanBeRead(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	file := filepath.Join(dir, "c.yaml")
	yaml := `connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: oauth, issuer: "https://a.example.com", client: {mode: preregistered, id: x, secretFile: ` + secret + `}}}]`
	if err := os.WriteFile(file, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(file, Options{}); err == nil || !strings.Contains(err.Error(), "secretFile") {
		t.Fatalf("a missing secret file: %v", err)
	}
	_ = os.WriteFile(secret, []byte(" \n"), 0o600)
	if _, err := Load(file, Options{}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("an empty secret file: %v", err)
	}
	_ = os.WriteFile(secret, []byte("s3cret\n"), 0o600)
	if cs, err := Load(file, Options{}); err != nil || len(cs) != 1 {
		t.Fatalf("%v", err)
	}
	if _, err := Load("", Options{}); err == nil {
		t.Fatal("no path")
	}
}
