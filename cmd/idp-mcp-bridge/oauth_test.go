package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"idp-mcp-bridge/internal/config"
	"idp-mcp-bridge/internal/grants"
	"idp-mcp-bridge/internal/oauth"
)

func oauthEnv(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	if err := os.WriteFile(keys, []byte("k1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"IDP_BRIDGE_DATABASE_URL": "postgres://u:p@db:5432/bridge", "IDP_BRIDGE_ENCRYPTION_KEYS_FILE": keys,
		"IDP_BRIDGE_REDIRECT_URI": "https://workspace.example.com/oauth/callback", "IDP_BRIDGE_OIDC_ISSUER": "https://keycloak.example.com/realms/idp",
		"IDP_BRIDGE_API_AUDIENCE": "idp-mcp-bridge", "IDP_BRIDGE_WORKSPACE_CLIENT": "idp-workspace"}
}

func TestTheOAuthSettingsAreRequiredAndCheckedWhenAConnectionNeedsThem(t *testing.T) {
	o, err := loadOAuthSettings(envOf(oauthEnv(t)), nil)
	if err != nil || o.tenantClaim != "tenant_id" || o.jwksURL != "https://keycloak.example.com/realms/idp/protocol/openid-connect/certs" || o.keys.Current() != "k1" {
		t.Fatalf("%+v %v", o, err)
	}
	cases := []struct {
		name string
		mod  map[string]string
		want string
	}{
		{"no database", map[string]string{"IDP_BRIDGE_DATABASE_URL": ""}, "IDP_BRIDGE_DATABASE_URL"},
		{"both the URL and the file", map[string]string{"IDP_BRIDGE_DATABASE_URL_FILE": "/x"}, "both set"},
		{"no key file", map[string]string{"IDP_BRIDGE_ENCRYPTION_KEYS_FILE": ""}, "IDP_BRIDGE_ENCRYPTION_KEYS_FILE"},
		{"a key file that is not one", map[string]string{"IDP_BRIDGE_ENCRYPTION_KEYS_FILE": "/etc/hostname"}, "IDP_BRIDGE_ENCRYPTION_KEYS_FILE"},
		{"no redirect address", map[string]string{"IDP_BRIDGE_REDIRECT_URI": ""}, "IDP_BRIDGE_REDIRECT_URI"},
		{"a redirect address over http", map[string]string{"IDP_BRIDGE_REDIRECT_URI": "http://workspace.example.com/cb"}, "IDP_BRIDGE_REDIRECT_URI"},
		{"a redirect address with a fragment", map[string]string{"IDP_BRIDGE_REDIRECT_URI": "https://workspace.example.com/cb#x"}, "IDP_BRIDGE_REDIRECT_URI"},
		{"a private redirect address", map[string]string{"IDP_BRIDGE_REDIRECT_URI": "https://10.0.0.1/cb"}, "IDP_BRIDGE_REDIRECT_URI"},
		{"no issuer", map[string]string{"IDP_BRIDGE_OIDC_ISSUER": ""}, "IDP_BRIDGE_OIDC_ISSUER"},
		{"no audience", map[string]string{"IDP_BRIDGE_API_AUDIENCE": ""}, "IDP_BRIDGE_API_AUDIENCE"},
		{"no workspace client", map[string]string{"IDP_BRIDGE_WORKSPACE_CLIENT": ""}, "IDP_BRIDGE_WORKSPACE_CLIENT"},
		{"keys over http", map[string]string{"IDP_BRIDGE_OIDC_JWKS_URL": "http://keycloak/certs"}, "IDP_BRIDGE_OIDC_JWKS_URL"},
	}
	for _, c := range cases {
		e := oauthEnv(t)
		for k, v := range c.mod {
			e[k] = v
		}
		if _, err := loadOAuthSettings(envOf(e), nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// http for the keys is an explicit choice; a test origin may be an http redirect address
	e := oauthEnv(t)
	e["IDP_BRIDGE_OIDC_JWKS_URL"], e["IDP_BRIDGE_OIDC_ALLOW_HTTP"], e["IDP_BRIDGE_REDIRECT_URI"] = "http://keycloak/certs", "true", "http://127.0.0.1:9/cb"
	if _, err := loadOAuthSettings(envOf(e), map[string]bool{"127.0.0.1:9": true}); err != nil {
		t.Fatal(err)
	}
}

func TestOAuthIsOnlyNeededForConnectionsThatUseIt(t *testing.T) {
	cs, err := config.Parse([]byte(`connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: none}}]`), config.Options{})
	if err != nil || hasOAuth(cs) {
		t.Fatal("a bridge of open services needs no database")
	}
	cs, _ = config.Parse([]byte(`connections: [{id: a, title: A, endpoint: "https://a.example.com/mcp", authorization: {mode: oauth, issuer: "https://as.example.com", client: {mode: cimd, document: "https://w.example.com/c.json"}}}]`), config.Options{})
	if !hasOAuth(cs) {
		t.Fatal("an oauth connection")
	}
}

func TestTheRevokeCommandTakesAMemberOrAConnectionAndNothingElse(t *testing.T) {
	st := grants.NewMemory()
	svc := &oauth.Service{Store: st}
	for _, g := range []grants.Grant{{Key: grants.Key{Tenant: "acme", Member: "bob", Connection: "notes"}}, {Key: grants.Key{Tenant: "acme", Member: "bob", Connection: "crm"}}, {Key: grants.Key{Tenant: "acme", Member: "alice", Connection: "notes"}}} {
		_ = st.Put(context.Background(), g)
	}
	run := func(args ...string) (string, error) {
		var out bytes.Buffer
		err := revokeCmd(context.Background(), args, svc, &out)
		return out.String(), err
	}
	for _, bad := range [][]string{{}, {"--member", "bob"}, {"--tenant", "acme"}, {"--bogus"}} {
		if _, err := run(bad...); err == nil {
			t.Errorf("%v: accepted", bad)
		}
	}
	if out, err := run("--tenant", "acme", "--member", "bob", "--connection", "crm"); err != nil || !strings.Contains(out, "deleted 1") && !strings.Contains(out, "revoked and deleted 1") {
		t.Fatalf("%q %v", out, err)
	}
	if g, _ := st.ForMember(context.Background(), "acme", "bob"); len(g) != 1 || g[0].Connection != "notes" {
		t.Fatalf("%+v", g)
	}
	if out, err := run("--connection", "notes"); err != nil || !strings.Contains(out, "deleted 2") {
		t.Fatalf("%q %v", out, err)
	}
}

func TestTheDatabaseCommandsNeedTheOwnersURLAndNothingElse(t *testing.T) {
	run := func(env map[string]string, args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := databaseCmd(context.Background(), args, envOf(env), &out, &errb)
		return code, errb.String()
	}
	if code, msg := run(nil, "migrate"); code != 1 || !strings.Contains(msg, "IDP_BRIDGE_MIGRATION_DATABASE_URL") {
		t.Fatalf("%d %q", code, msg)
	}
	owner := map[string]string{"IDP_BRIDGE_MIGRATION_DATABASE_URL": "postgres://owner:pw@127.0.0.1:1/x"}
	if code, msg := run(owner, "ensure-login"); code != 1 || !strings.Contains(msg, "usage") {
		t.Fatalf("%d %q", code, msg)
	}
	if code, msg := run(owner, "ensure-login", "idp_bridge_svc"); code != 1 || !strings.Contains(msg, "IDP_BRIDGE_APP_DB_PASSWORD") {
		t.Fatalf("%d %q", code, msg)
	}
	both := map[string]string{"IDP_BRIDGE_MIGRATION_DATABASE_URL": "x", "IDP_BRIDGE_MIGRATION_DATABASE_URL_FILE": "/y"}
	if code, msg := run(both, "migrate"); code != 1 || !strings.Contains(msg, "both set") {
		t.Fatalf("%d %q", code, msg)
	}
	// unreachable: the message does not echo the URL (it holds the password)
	if code, msg := run(owner, "migrate"); code != 1 || strings.Contains(msg, "pw@") {
		t.Fatalf("%d %q", code, msg)
	}
}
