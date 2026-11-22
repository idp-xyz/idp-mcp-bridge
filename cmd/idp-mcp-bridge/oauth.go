package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"idp-mcp-bridge/internal/addr"
	"idp-mcp-bridge/internal/config"
	"idp-mcp-bridge/internal/grants"
	"idp-mcp-bridge/internal/idauth"
	"idp-mcp-bridge/internal/oauth"
	"idp-mcp-bridge/internal/sealer"
)

// oauthSettings are what OAuth needs besides the connections (ADR-0001 D24 to D28). They are required as soon as one connection
// has `authorization.mode: oauth`, and not read at all otherwise, so a bridge that only fronts open services needs no database.
type oauthSettings struct {
	databaseURL string
	keys        *sealer.Keys
	redirectURI string

	oidcIssuer, jwksURL, audience, workspaceClient, tenantClaim string
	allowHTTP                                                   bool
	caFile                                                      string
	// the operators who may authorize reviewer accounts (ADR-0001 D33): no default, unset means no one
	reviewerRole, reviewerTenant, rolesClaim string
}

func hasOAuth(cs []config.Connection) bool {
	for _, c := range cs {
		if c.Authorization.Mode == config.AuthOAuth {
			return true
		}
	}
	return false
}

// secretSetting reads a setting that may hold a password: the environment variable name, or the file name_FILE names (a
// mounted Secret), not both.
func secretSetting(getenv func(string) string, name string) (string, error) {
	v, file := getenv(name), getenv(name+"_FILE")
	switch {
	case v != "" && file != "":
		return "", fmt.Errorf("%s and %s_FILE are both set: set one", name, name)
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", name, err)
		}
		if v = strings.TrimSpace(string(b)); v == "" {
			return "", fmt.Errorf("%s_FILE: the file is empty", name)
		}
	}
	return v, nil
}

func loadOAuthSettings(getenv func(string) string, testOrigins map[string]bool) (*oauthSettings, error) {
	o := &oauthSettings{}
	var err error
	if o.databaseURL, err = secretSetting(getenv, "IDP_BRIDGE_DATABASE_URL"); err != nil {
		return nil, err
	}
	if o.databaseURL == "" {
		return nil, errors.New("IDP_BRIDGE_DATABASE_URL (or IDP_BRIDGE_DATABASE_URL_FILE) is not set: a connection with authorization mode oauth needs the database that holds the members' grants")
	}
	if getenv("IDP_BRIDGE_ENCRYPTION_KEYS_FILE") == "" {
		return nil, errors.New("IDP_BRIDGE_ENCRYPTION_KEYS_FILE is not set: the file of the keys that seal the members' tokens (docs/RUNBOOK.md 5)")
	}
	if o.keys, err = sealer.Load(getenv("IDP_BRIDGE_ENCRYPTION_KEYS_FILE")); err != nil {
		return nil, fmt.Errorf("IDP_BRIDGE_ENCRYPTION_KEYS_FILE: %w", err)
	}
	if o.redirectURI = getenv("IDP_BRIDGE_REDIRECT_URI"); o.redirectURI == "" {
		return nil, errors.New("IDP_BRIDGE_REDIRECT_URI is not set: the Workspace's callback page, the redirect address of every connection")
	}
	a, err := addr.TargetWith(o.redirectURI, addr.Options{TestOrigins: testOrigins})
	if err != nil || (a.Scheme != "https" && !a.Exempt) || strings.Contains(o.redirectURI, "#") {
		return nil, errors.New("IDP_BRIDGE_REDIRECT_URI must be a public https address without a fragment (a test origin may be http)")
	}
	o.oidcIssuer = getenv("IDP_BRIDGE_OIDC_ISSUER")
	o.audience = getenv("IDP_BRIDGE_API_AUDIENCE")
	o.workspaceClient = getenv("IDP_BRIDGE_WORKSPACE_CLIENT")
	o.tenantClaim = env(getenv, "IDP_BRIDGE_TENANT_CLAIM", "tenant_id")
	o.allowHTTP = getenv("IDP_BRIDGE_OIDC_ALLOW_HTTP") == "true"
	o.caFile = getenv("IDP_BRIDGE_OIDC_CA_FILE")
	o.reviewerRole, o.reviewerTenant = getenv("IDP_BRIDGE_REVIEWER_ROLE"), getenv("IDP_BRIDGE_REVIEWER_TENANT")
	o.rolesClaim = env(getenv, "IDP_BRIDGE_ROLES_CLAIM", "roles")
	if o.reviewerRole == "" && o.reviewerTenant != "" {
		return nil, errors.New("IDP_BRIDGE_REVIEWER_TENANT is set without IDP_BRIDGE_REVIEWER_ROLE: the tenant narrows the role, and without a role no one is a reviewer")
	}
	for k, v := range map[string]string{"IDP_BRIDGE_OIDC_ISSUER": o.oidcIssuer, "IDP_BRIDGE_API_AUDIENCE": o.audience, "IDP_BRIDGE_WORKSPACE_CLIENT": o.workspaceClient} {
		if v == "" {
			return nil, fmt.Errorf("%s is not set: the Workspace's calls to the internal API are verified against Keycloak (ADR-0001 D28)", k)
		}
	}
	o.jwksURL = env(getenv, "IDP_BRIDGE_OIDC_JWKS_URL", strings.TrimSuffix(o.oidcIssuer, "/")+"/protocol/openid-connect/certs")
	u, err := url.Parse(o.jwksURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(u.Scheme == "http" && o.allowHTTP)) {
		return nil, errors.New("IDP_BRIDGE_OIDC_JWKS_URL must be an https address (http only with IDP_BRIDGE_OIDC_ALLOW_HTTP=true: the keys that decide who may call are fetched from it)")
	}
	return o, nil
}

// jwksClient is the client for Keycloak's keys: in the cluster, so not the public-address client; no redirect, no environment
// proxy, bounded in time, with the operator's CA if there is one.
func (o *oauthSettings) jwksClient() (*http.Client, error) {
	tr := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableCompression: true}
	if o.caFile != "" {
		pem, err := os.ReadFile(o.caFile)
		if err != nil {
			return nil, fmt.Errorf("IDP_BRIDGE_OIDC_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("IDP_BRIDGE_OIDC_CA_FILE holds no certificate")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func (o *oauthSettings) verifier() (*idauth.Verifier, error) {
	hc, err := o.jwksClient()
	if err != nil {
		return nil, err
	}
	return &idauth.Verifier{Issuer: o.oidcIssuer, Audience: o.audience, AuthorizedParty: o.workspaceClient, TenantClaim: o.tenantClaim,
		ReviewerRole: o.reviewerRole, ReviewerTenant: o.reviewerTenant, RolesClaim: o.rolesClaim, Keys: &idauth.JWKS{URL: o.jwksURL, HTTP: hc}}, nil
}

// openStore opens the store as the service role. It does not migrate and runs no DDL: the schema is the migration Job's
// (`idp-mcp-bridge migrate`, as the owner), and the store refuses to open on a schema that is not at the version this binary
// expects, or as a role that could change it (ADR-0001 D25).
func (o *oauthSettings) openStore(ctx context.Context) (*grants.PG, error) {
	c, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	st, err := grants.Open(c, o.databaseURL)
	if err != nil {
		return nil, fmt.Errorf("IDP_BRIDGE_DATABASE_URL: %w", err)
	}
	return st, nil
}

// databaseCmd runs the two commands that prepare the database, as idp-web, idp-mcp and idp-host do: `migrate` (apply the embedded
// migrations as the schema owner, which also gives the role idp_bridge_app its privileges and nothing more) and `ensure-login USER`
// (create or update the login role the service runs as, a member of idp_bridge_app, with the password in IDP_BRIDGE_APP_DB_PASSWORD
// or _FILE). Both read the owner's URL from IDP_BRIDGE_MIGRATION_DATABASE_URL (or _FILE), which only the migration Job has. They
// need no other setting. It returns the exit status.
func databaseCmd(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	owner, err := secretSetting(getenv, "IDP_BRIDGE_MIGRATION_DATABASE_URL")
	if err == nil && owner == "" {
		err = errors.New("IDP_BRIDGE_MIGRATION_DATABASE_URL is not set: the schema owner's URL (or IDP_BRIDGE_MIGRATION_DATABASE_URL_FILE)")
	}
	if err == nil {
		switch args[0] {
		case "migrate":
			var applied []string
			if applied, err = grants.Migrate(ctx, owner); err == nil {
				fmt.Fprintf(stdout, "OK: %d migration(s) applied %v\n", len(applied), applied)
			}
		case "ensure-login":
			var password string
			if len(args) != 2 {
				err = errors.New("usage: ensure-login USER (the password in IDP_BRIDGE_APP_DB_PASSWORD or IDP_BRIDGE_APP_DB_PASSWORD_FILE)")
			} else if password, err = secretSetting(getenv, "IDP_BRIDGE_APP_DB_PASSWORD"); err == nil && password == "" {
				err = errors.New("IDP_BRIDGE_APP_DB_PASSWORD is not set (or IDP_BRIDGE_APP_DB_PASSWORD_FILE)")
			}
			if err == nil {
				if err = grants.EnsureLogin(ctx, owner, args[1], password); err == nil {
					fmt.Fprintf(stdout, "OK: login role %s is a member of idp_bridge_app\n", args[1])
				}
			}
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "idp-mcp-bridge", args[0]+":", err)
		return 1
	}
	return 0
}

// service assembles the OAuth service over a store.
func (o *oauthSettings) service(conns []config.Connection, st grants.Store, hc *http.Client, probe func(context.Context, string) string, testOrigins map[string]bool, log *slog.Logger) *oauth.Service {
	f := &oauth.Fetcher{HTTP: hc, TestOrigins: testOrigins}
	return &oauth.Service{Connections: conns, RedirectURI: o.redirectURI, Store: st, Sealer: o.keys, F: f, Log: log,
		Disc: &oauth.Discoverer{F: f, Probe: probe}}
}

// ---- operator subcommands ----

// revokeCmd is `idp-mcp-bridge revoke --tenant T --member M [--connection C]` or `revoke --connection C`: a member who left, or a
// connection that was withdrawn (ADR-0001 D29); the work is oauth.Service.RevokeMember and RevokeConnection. Automatic offboarding
// (the identity provider telling the bridge a member left) is not part of the bridge; ADR-0001 D29 records it as open.
func revokeCmd(ctx context.Context, args []string, svc *oauth.Service, stdout io.Writer) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "the member's tenant")
	member := fs.String("member", "", "the member's subject")
	connection := fs.String("connection", "", "only this connection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case (*member == "") != (*tenant == ""):
		return errors.New("--tenant and --member go together")
	case *member == "" && *connection == "":
		return errors.New("usage: revoke --tenant T --member M [--connection C]   or   revoke --connection C")
	case *member == "":
		n, err := svc.RevokeConnection(ctx, *connection)
		fmt.Fprintf(stdout, "deleted %d grants of connection %s (not revoked at their authorization servers)\n", n, *connection)
		return err
	}
	n, err := svc.RevokeMember(ctx, *tenant, *member, *connection)
	fmt.Fprintf(stdout, "revoked and deleted %d grants\n", n)
	return err
}

// resealCmd is `idp-mcp-bridge reseal`: see oauth.Reseal.
func resealCmd(ctx context.Context, o *oauthSettings, st grants.Store, stdout io.Writer) error {
	n, err := oauth.Reseal(ctx, o.keys, st)
	fmt.Fprintf(stdout, "re-sealed %d values under key %s\n", n, o.keys.Current())
	return err
}
