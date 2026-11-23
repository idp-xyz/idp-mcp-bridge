package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"idp-mcp-bridge/internal/config"
	"idp-mcp-bridge/internal/directory"
	"idp-mcp-bridge/internal/grants"
	"idp-mcp-bridge/internal/oauth"
	"idp-mcp-bridge/internal/reconcile"
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

func TestTheReviewerRoleHasNoDefaultAndATenantNeedsARole(t *testing.T) {
	o, err := loadOAuthSettings(envOf(oauthEnv(t)), nil)
	if err != nil || o.reviewerRole != "" || o.reviewerTenant != "" || o.rolesClaim != "roles" {
		t.Fatalf("%+v %v", o, err)
	}
	e := oauthEnv(t)
	e["IDP_BRIDGE_REVIEWER_ROLE"], e["IDP_BRIDGE_REVIEWER_TENANT"], e["IDP_BRIDGE_ROLES_CLAIM"] = "idp-reviewer", "acme", "realm_roles"
	if o, err = loadOAuthSettings(envOf(e), nil); err != nil || o.reviewerRole != "idp-reviewer" || o.reviewerTenant != "acme" || o.rolesClaim != "realm_roles" {
		t.Fatalf("%+v %v", o, err)
	}
	if v, _ := o.verifier(); v.ReviewerRole != "idp-reviewer" || v.ReviewerTenant != "acme" || v.RolesClaim != "realm_roles" {
		t.Fatal("the verifier does not carry the settings")
	}
	delete(e, "IDP_BRIDGE_REVIEWER_ROLE")
	if _, err := loadOAuthSettings(envOf(e), nil); err == nil || !strings.Contains(err.Error(), "IDP_BRIDGE_REVIEWER_TENANT") {
		t.Fatalf("%v", err)
	}
}

func TestTheOffboardingAndDirectorySettingsAreCheckedAndTheRouteAndTheDirectoryAreOffByDefault(t *testing.T) {
	o, err := loadOAuthSettings(envOf(oauthEnv(t)), nil)
	if err != nil || len(o.offboardClients) != 0 || o.directory != "none" || o.reconcileInterval != 15*time.Minute {
		t.Fatalf("%+v %v", o, err)
	}
	e := oauthEnv(t)
	e["IDP_BRIDGE_OFFBOARD_CLIENTS"], e["IDP_BRIDGE_RECONCILE_INTERVAL"] = " lifecycle , other,,", "30s"
	if o, err = loadOAuthSettings(envOf(e), nil); err != nil || strings.Join(o.offboardClients, ",") != "lifecycle,other" || o.reconcileInterval != 30*time.Second {
		t.Fatalf("%+v %v", o, err)
	}
	if v, _ := o.verifier(); strings.Join(v.ServiceClients, ",") != "lifecycle,other" {
		t.Fatal("the verifier does not carry the allow-list")
	}
	e["IDP_BRIDGE_RECONCILE_INTERVAL"] = "0"
	if o, err = loadOAuthSettings(envOf(e), nil); err != nil || o.reconcileInterval != 0 {
		t.Fatalf("0 is off: %v", err)
	}
	for _, bad := range []string{"-5m", "500ms", "soon", "15"} {
		e["IDP_BRIDGE_RECONCILE_INTERVAL"] = bad
		if _, err := loadOAuthSettings(envOf(e), nil); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	kc := map[string]string{"IDP_BRIDGE_DIRECTORY": "keycloak-dev", "IDP_BRIDGE_KEYCLOAK_URL": "https://keycloak.example.com", "IDP_BRIDGE_KEYCLOAK_REALM": "idp",
		"IDP_BRIDGE_KEYCLOAK_CLIENT_ID": "bridge-directory", "IDP_BRIDGE_KEYCLOAK_CLIENT_SECRET_FILE": "/etc/idp/kc/secret"}
	e = oauthEnv(t)
	for k, v := range kc {
		e[k] = v
	}
	if o, err = loadOAuthSettings(envOf(e), nil); err != nil || o.keycloak.tenantAttribute != "tenant_id" || o.keycloak.realm != "idp" {
		t.Fatalf("%+v %v", o, err)
	}
	for k := range kc {
		if k == "IDP_BRIDGE_DIRECTORY" {
			continue
		}
		e2 := oauthEnv(t)
		for k2, v := range kc {
			e2[k2] = v
		}
		delete(e2, k)
		if _, err := loadOAuthSettings(envOf(e2), nil); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("without %s: %v", k, err)
		}
	}
	e["IDP_BRIDGE_KEYCLOAK_URL"] = "http://keycloak:8080"
	if _, err := loadOAuthSettings(envOf(e), nil); err == nil {
		t.Error("an http Keycloak without the explicit opt-in")
	}
	e["IDP_BRIDGE_DIRECTORY"] = "ldap"
	if _, err := loadOAuthSettings(envOf(e), nil); err == nil {
		t.Error("an unknown directory")
	}
}

type onlyDir struct{ st directory.Status }

func (d onlyDir) Lookup(context.Context, string, string) (directory.Status, error) { return d.st, nil }

type countOff struct{ n int }

func (c *countOff) AuthorizerLeft(context.Context, string, string, string, string) (int, error) {
	return 0, nil
}

func (c *countOff) Offboard(context.Context, oauth.OffboardRequest) (oauth.OffboardResult, error) {
	c.n++
	return oauth.OffboardResult{}, nil
}

func TestTheReconcileCommandRunsOneRoundAndForceGoesPastTheBrake(t *testing.T) {
	st := grants.NewMemory()
	for i := 0; i < 10; i++ {
		_ = st.Put(context.Background(), grants.Grant{Key: grants.Key{Tenant: "acme", Member: string(rune('a' + i)), Connection: "notes"}})
	}
	off := &countOff{}
	rc := &reconcile.Reconciler{Store: st, Dir: onlyDir{directory.Deleted}, Off: off}
	run := func(rc *reconcile.Reconciler, args ...string) (string, error) {
		var out bytes.Buffer
		err := reconcileCmd(context.Background(), args, rc, &out)
		return out.String(), err
	}
	if _, err := run(rc); err == nil {
		t.Error("without --now")
	}
	if _, err := run(nil, "--now"); err == nil || !strings.Contains(err.Error(), "IDP_BRIDGE_DIRECTORY") {
		t.Errorf("no directory: %v", err)
	}
	out, err := run(rc, "--now")
	if err != nil || off.n != 0 || !strings.Contains(out, "brake held") {
		t.Fatalf("%q %v (%d)", out, err, off.n)
	}
	out, err = run(rc, "--now", "--force")
	if err != nil || off.n != 10 || !strings.Contains(out, "10 offboarded") {
		t.Fatalf("%q %v (%d)", out, err, off.n)
	}
}
