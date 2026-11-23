// idp-mcp-bridge: the MCP server that sits behind the idp-mcp gateway and calls third-party MCP servers on behalf of
// members (ADR-0001; plan: docs/adr/idp-mcp-bridge-oauth-plan.md in the platform repository).
//
// Connections, one MCP endpoint per connection for the gateway, the client toward the third party with the address rules, the
// limits and the breaker (B1), and OAuth per member (B2): each member authorizes a third-party service once, the grants are
// sealed in PostgreSQL, and the call goes out with that member's own token. A connection that needs no token works without any
// of the OAuth settings. Configuration is by environment:
//
//	IDP_BRIDGE_CONFIG_FILE       the YAML file that lists the connections (docs/RUNBOOK.md 4). Required
//	IDP_BRIDGE_CALLER_KEYS_FILE  PEM public key(s) of the gateway (P-256; the gateway's IDP_GATEWAY_CALLER_KEY_FILE).
//	                             Required: every tools/call must carry the gateway's assertion
//	IDP_BRIDGE_BASE_URL          the address the gateway reaches the bridge at, without a path, for example
//	                             http://idp-mcp-bridge.idp-mcp-bridge.svc.cluster.local:8680. The audience of a
//	                             connection's assertion is this + /mcp/<id>, which must be the endpoint registered in
//	                             idp-mcp. Required
//	IDP_BRIDGE_LISTEN            address of /mcp/<id> (default 127.0.0.1:8680); a non-loopback address needs
//	IDP_BRIDGE_PRIVATE_NETWORK   =true, the operator's statement that only the gateway reaches it
//	IDP_BRIDGE_API_LISTEN        address of the internal API of the Workspace (default 127.0.0.1:8681)
//	IDP_BRIDGE_METRICS           address of /healthz /readyz /metrics (default 127.0.0.1:9680)
//	IDP_BRIDGE_EGRESS_PROXY      the corporate proxy to reach third parties through, http(s)://host:port, no credentials
//	IDP_BRIDGE_MAX_RESULT_BYTES  longest answer, or event of a stream, accepted from a third party (default 1 MiB, at most 16 MiB)
//	IDP_BRIDGE_MAX_STREAM_BYTES  most bytes read from one stream (default 4 MiB, at most 16 MiB)
//	IDP_BRIDGE_CALL_TIMEOUT_S    how long one call to a third party may take (default 60)
//
//	OAuth, required as soon as one connection has `authorization.mode: oauth` (docs/RUNBOOK.md 5):
//	IDP_BRIDGE_DATABASE_URL      the PostgreSQL URL of the grants; or IDP_BRIDGE_DATABASE_URL_FILE (a mounted Secret). A member of
//	                             idp_bridge_app: DML on three tables and nothing else. The server runs no DDL and does not migrate; it
//	                             refuses to start on another schema version, or as a role that could change the schema
//	IDP_BRIDGE_ENCRYPTION_KEYS_FILE  the keys that seal the tokens: one `<id>:<base64 of 32 bytes>` a line, the first seals and all open
//	IDP_BRIDGE_REDIRECT_URI      the Workspace's callback page, the redirect address of every connection (public https)
//	IDP_BRIDGE_OIDC_ISSUER       Keycloak's realm: the Workspace's calls to the internal API are verified against its keys
//	IDP_BRIDGE_OIDC_JWKS_URL     its keys (default <issuer>/protocol/openid-connect/certs); https, or http with
//	IDP_BRIDGE_OIDC_ALLOW_HTTP   =true; IDP_BRIDGE_OIDC_CA_FILE adds a CA for it
//	IDP_BRIDGE_REVIEWER_ROLE     the realm role (in the `roles` claim, IDP_BRIDGE_ROLES_CLAIM) of the operators who may authorize reviewer
//	                             accounts; IDP_BRIDGE_REVIEWER_TENANT narrows it to one tenant. No default: unset, no one can
//	IDP_BRIDGE_OFFBOARD_CLIENTS  comma-separated OIDC clients (azp) whose client-credentials tokens may call POST /internal/v1/members/offboard
//	                             (a member has left); empty: the route is disabled
//	IDP_BRIDGE_DIRECTORY         none (default) or keycloak-dev (for development and tests only): where the reconciliation asks whether a member
//	                             is still one; IDP_BRIDGE_RECONCILE_INTERVAL (default 15m, 0 = off); the adapter's IDP_BRIDGE_KEYCLOAK_URL,
//	                             _REALM, _CLIENT_ID, _CLIENT_SECRET_FILE, _TENANT_ATTRIBUTE (tenant_id)
//	IDP_BRIDGE_API_AUDIENCE      what the Workspace's token is exchanged for (its `aud`)
//	IDP_BRIDGE_WORKSPACE_CLIENT  the only client (`azp`) whose token is accepted; IDP_BRIDGE_TENANT_CLAIM names the tenant claim (tenant_id)
//
//	IDP_BRIDGE_TEST_ORIGINS      for tests only: comma-separated host:port pairs that may be contacted although they are
//	                             not public https addresses (ADR-0001 D6). Nothing else is exempted
//
// `idp-mcp-bridge check-config` validates the file and the settings and prints the connections, then exits.
// `idp-mcp-bridge migrate` applies the schema as the schema owner (IDP_BRIDGE_MIGRATION_DATABASE_URL[_FILE], held only by the
// migration Job) and `ensure-login USER` makes the service's login role (password in IDP_BRIDGE_APP_DB_PASSWORD[_FILE]); neither
// needs another setting. `revoke --tenant T --member M [--connection C]` (or `revoke --connection C`)
// removes a member's grants, or a connection's, for the operator; `reseal` moves every sealed value to the current key. A
// configuration error is written to stderr and the exit status is 2.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"idp-mcp-bridge/internal/api"
	"idp-mcp-bridge/internal/app"
	"idp-mcp-bridge/internal/auth"
	"idp-mcp-bridge/internal/bridge"
	"idp-mcp-bridge/internal/egress"
	"idp-mcp-bridge/internal/grants"
	"idp-mcp-bridge/internal/idauth"
	"idp-mcp-bridge/internal/oauth"
	"idp-mcp-bridge/internal/reconcile"

	// The image is FROM scratch and holds no CA certificates. This import registers Mozilla's roots as the fallback of
	// crypto/x509, which Go uses when the system has none (ADR-0001 D18).
	_ "golang.org/x/crypto/x509roots/fallback"
)

// version is stamped by the build (deploy/build.sh).
var version = "dev"

func fatal(args ...any) {
	fmt.Fprintln(os.Stderr, args...)
	os.Exit(2)
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) > 1 && (os.Args[1] == "migrate" || os.Args[1] == "ensure-login") {
		os.Exit(databaseCmd(context.Background(), os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
	}
	s, err := loadSettings(os.Getenv)
	if err != nil {
		fatal(err)
	}
	conns, err := s.connections()
	if err != nil {
		fatal("IDP_BRIDGE_CONFIG_FILE:", err)
	}
	sub := ""
	if len(os.Args) > 1 {
		sub = os.Args[1]
	}
	if sub == "check-config" {
		for _, c := range conns {
			fmt.Printf("%s\t%s\t%s\t%s\n", c.ID, c.Authorization.Mode, c.Parsed.URL(), app.Audience(s.baseURL, c.ID))
		}
		return
	}
	if len(s.testOrigins) > 0 {
		log.Warn("IDP_BRIDGE_TEST_ORIGINS exempts these origins from the address rules: for tests only", "origins", len(s.testOrigins))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// OAuth is on as soon as one connection needs it; then its settings are required (ADR-0001 D24)
	var os_ *oauthSettings
	var store *grants.PG
	var svc *oauth.Service
	httpClient := egress.NewClient(egress.Options{TestOrigins: s.testOrigins, Proxy: s.proxy})
	opts := app.Options{BaseURL: s.baseURL, CallerKeysPEM: s.callerKeys, Version: version, HTTP: httpClient,
		MaxResult: s.maxResult, MaxStream: s.maxStream, CallTimeout: s.callTimeout}
	met := bridge.NewMetrics()
	var tokens auth.TokenSource = auth.NoTokens{}        // B1's, for a bridge with no oauth connection
	var reviewer auth.ReviewerSource = auth.NoReviewer{} // B1's: listings go out without a token
	var apiSvc api.Service = api.Unimplemented{}
	var apiAuth api.Authenticator = api.Unimplemented{}
	if hasOAuth(conns) || sub == "revoke" || sub == "reseal" || sub == "reconcile" {
		if os_, err = loadOAuthSettings(os.Getenv, s.testOrigins); err != nil {
			fatal(err)
		}
		if store, err = os_.openStore(ctx); err != nil {
			fatal(err)
		}
		defer store.Close()
		svc = os_.service(conns, store, httpClient, app.Prober(conns, httpClient, opts), s.testOrigins, log)
		svc.Counters = met
	}
	var reconciler *reconcile.Reconciler
	if os_ != nil {
		dir, err := os_.buildDirectory(log)
		if err != nil {
			fatal(err)
		}
		if dir != nil {
			reconciler = &reconcile.Reconciler{Store: store, Dir: dir, Off: svc, Log: log, Counters: met, Interval: os_.reconcileInterval}
		}
	}
	switch sub {
	case "revoke":
		if err := revokeCmd(ctx, os.Args[2:], svc, os.Stdout); err != nil {
			fatal(err)
		}
		return
	case "reconcile":
		if err := reconcileCmd(ctx, os.Args[2:], reconciler, os.Stdout); err != nil {
			fatal(err)
		}
		return
	case "reseal":
		if err := resealCmd(ctx, os_, store, os.Stdout); err != nil {
			fatal(err)
		}
		return
	case "":
	default:
		fatal("unknown command", sub, "(check-config, migrate, ensure-login, revoke, reseal, reconcile; no argument runs the server)")
	}
	if svc != nil {
		tokens, apiSvc, reviewer = svc, svc, oauth.ReviewerSource{S: svc}
		if apiAuth, err = os_.verifier(); err != nil {
			fatal(err)
		}
		if os_.allowHTTP {
			log.Warn("IDP_BRIDGE_OIDC_ALLOW_HTTP: Keycloak's keys are fetched over http")
		}
		go func() { // pending authorizations that were never finished
			for t := time.NewTicker(time.Minute); ; {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if _, err := svc.Sweep(ctx); err != nil {
						log.Error("the sweep of expired authorizations failed")
					}
				}
			}
		}()
	}
	opts.Deps = bridge.Deps{Tokens: tokens, Reviewer: reviewer, Log: log, Metrics: met}
	handler, err := app.Handler(conns, opts)
	if err != nil {
		fatal(err)
	}
	log.Info("configured", "connections", len(conns), "oauth", svc != nil, "proxy", s.proxy != nil, "maxResultBytes", s.maxResult, "maxStreamBytes", s.maxStream)

	mcpSrv := &http.Server{Addr: s.listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: s.callTimeout + 30*time.Second}
	apiHandler := api.New(apiAuth, apiSvc)
	if svc != nil && len(os_.offboardClients) > 0 {
		v, _ := apiAuth.(*idauth.Verifier)
		apiHandler.EnableOffboarding(v, oauth.OffboardAPI{S: svc})
		log.Info("the member-left route is enabled", "clients", len(os_.offboardClients))
	}
	if reconciler != nil && reconciler.Interval > 0 {
		go reconciler.Run(ctx)
		log.Info("members are reconciled against the directory", "directory", os_.directory, "interval", reconciler.Interval.String())
	}
	apiSrv := &http.Server{Addr: s.apiListen, Handler: apiHandler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second}
	ops := http.NewServeMux()
	ops.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	ops.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if store != nil && store.Ping(r.Context()) != nil {
			http.Error(w, "not ready: database not reachable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ready")
	})
	ops.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		met.Write(w)
	})
	opsSrv := &http.Server{Addr: s.metrics, Handler: ops, ReadHeaderTimeout: 10 * time.Second}

	errc := make(chan error, 3)
	go func() { errc <- mcpSrv.ListenAndServe() }()
	go func() { errc <- apiSrv.ListenAndServe() }()
	go func() { errc <- opsSrv.ListenAndServe() }()
	log.Info("idp-mcp-bridge listening", "mcp", s.listen, "api", s.apiListen, "ops", s.metrics, "version", version)
	exit := 0
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("server", "err", err)
			exit = 1
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = mcpSrv.Shutdown(shutdown)
	_ = apiSrv.Shutdown(shutdown)
	_ = opsSrv.Shutdown(shutdown)
	if exit != 0 {
		cancel()
		os.Exit(exit)
	}
}
