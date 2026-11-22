// Package app assembles the bridge: one MCP endpoint per connection, each with its own verifier of the gateway's
// assertion (ADR-0001 D2, D5), its own client toward the third party and its own limits and breaker.
package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"idp-mcp-bridge/internal/bridge"
	"idp-mcp-bridge/internal/config"
	"idp-mcp-bridge/internal/egress"
	"idp-mcp-bridge/internal/mcp"
	"idp-mcp-bridge/internal/upstream"
)

// Options of Handler.
type Options struct {
	// BaseURL is the address the gateway reaches the bridge at, as it is registered in idp-mcp, without a path
	// (http://idp-mcp-bridge.idp-mcp-bridge.svc.cluster.local:8680). The audience of a connection's assertion is
	// BaseURL + "/mcp/" + id, character for character the endpoint registered at the gateway.
	BaseURL string
	// CallerKeysPEM are the gateway's public keys (P-256).
	CallerKeysPEM []byte
	Version       string
	Egress        egress.Options
	// HTTP, if set, is the client toward third parties; the one main shares with the OAuth flow, so that both go through the
	// same checked dialer. Otherwise one is made from Egress.
	HTTP *http.Client
	// MaxResult and MaxStream bound the third party's answers (upstream.DefaultMax*) if zero.
	MaxResult, MaxStream int64
	// CallTimeout bounds one request to the third party and its answer, the gateway's own for an external target (60 s).
	CallTimeout time.Duration
	Deps        bridge.Deps
}

// Path of a connection's endpoint.
func Path(id string) string { return "/mcp/" + id }

// Audience of a connection under base.
func Audience(base, id string) string { return strings.TrimSuffix(base, "/") + Path(id) }

// ValidateBaseURL checks the address the audience is made from.
func ValidateBaseURL(base string) error {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return fmt.Errorf("%q is not an http or https address without a path (for example http://idp-mcp-bridge.idp-mcp-bridge.svc.cluster.local:8680)", base)
	}
	return nil
}

// Handler returns the handler of the MCP side: /mcp/<id> for each connection and nothing else.
func Handler(cs []config.Connection, o Options) (http.Handler, error) {
	if err := ValidateBaseURL(o.BaseURL); err != nil {
		return nil, err
	}
	if o.Deps.Tokens == nil || o.Deps.Reviewer == nil {
		return nil, errors.New("a token source and a reviewer source are required (B1 has auth.NoTokens and auth.NoReviewer)")
	}
	if o.CallTimeout == 0 {
		o.CallTimeout = 60 * time.Second
	}
	httpClient := o.HTTP
	if httpClient == nil {
		httpClient = egress.NewClient(o.Egress)
	}
	mux := http.NewServeMux()
	for _, c := range cs {
		verifier, err := mcp.NewCallerVerifier(o.CallerKeysPEM, Audience(o.BaseURL, c.ID))
		if err != nil {
			return nil, fmt.Errorf("connection %q: %w", c.ID, err)
		}
		client := &upstream.Client{HTTP: httpClient, Endpoint: c.Parsed.URL(), MaxResult: o.MaxResult, MaxStream: o.MaxStream}
		conn := bridge.New(c, client, o.Deps)
		srv := mcp.New(c.ID, o.Version, "", conn, verifier)
		srv.Log = o.Deps.Log
		mux.Handle(Path(c.ID), withTimeout(srv, o.CallTimeout))
	}
	return mux, nil
}

func withTimeout(h http.Handler, d time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Prober returns the function that asks a connection's third party for the WWW-Authenticate challenge of an unauthenticated
// request (an unauthenticated tools/list), for the discovery of its authorization server (RFC 9728). "" if there is none.
func Prober(cs []config.Connection, hc *http.Client, o Options) func(ctx context.Context, id string) string {
	clients := map[string]*upstream.Client{}
	for _, c := range cs {
		clients[c.ID] = &upstream.Client{HTTP: hc, Endpoint: c.Parsed.URL(), MaxResult: o.MaxResult, MaxStream: o.MaxStream}
	}
	return func(ctx context.Context, id string) string {
		cl := clients[id]
		if cl == nil {
			return ""
		}
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		_, err := cl.ListTools(ctx, "")
		var se *upstream.StatusError
		if errors.As(err, &se) {
			return se.Challenge
		}
		return ""
	}
}
