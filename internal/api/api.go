// Package api declares the internal API the Workspace calls (ADR-0001 D16): the page "connected services" and the
// OAuth callback, which lands on the Workspace and is handed on here (plan section 2). The service is
// internal/oauth.Service and the authenticator internal/idauth.Verifier; the Unimplemented stand-ins are what a bridge with no
// oauth connection answers with (501).
//
// # The authentication rule
//
// The Workspace calls with the member's own token, exchanged for the bridge's audience (RFC 8693), exactly as it
// calls idp-host (idp-workspace internal/dispatch/exchange.go, ADR-0001 D16 there: auth "exchange", the Workspace as
// the requesting client, cached per token and audience). The bridge verifies that token itself, against Keycloak's
// keys, and takes the tenant and the member from it: Authorization: Bearer <token>; the token's signature (JWKS of
// the realm the bridge is configured with), its issuer, its expiry, an audience that includes this bridge's own, its
// authorized party (azp) the Workspace's client and no other, and the tenant and subject claims. Nothing the request
// says besides the token names a member: not a path, a query, a header or a body field. A request without a token is
// 401; a token that fails any check is 401 without saying which.
//
// It is the member who authorizes, so this is never callable with the gateway's assertion, which names a member for
// a tool call and is made for another audience, and never with a service credential of the Workspace's own.
// The redirect address of the OAuth flow is the bridge's configuration, never a field of a request: a caller who
// could name it could send the code to an address of its own.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"idp-mcp-bridge/internal/auth"
)

// ErrNotImplemented is what B1 answers: 501.
var ErrNotImplemented = errors.New("not implemented: this is B2")

// ErrUnauthenticated: the token is missing or not good: 401.
var ErrUnauthenticated = errors.New("not authenticated")

// Statuses of a connection for a member.
const (
	StatusNotRequired  = "not_required" // the connection needs no token
	StatusNotConnected = "not_connected"
	StatusConnected    = "connected"
	StatusReauthorize  = "reauthorization_required" // the grant exists and cannot be used (the Reason says why)
)

// ConnectionStatus is one entry of the Workspace's list: what the member sees. It carries no address of the third
// party and nothing secret.
type ConnectionStatus struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	// Reason is a code from a fixed set, with reauthorization_required: insufficient_scope, issuer_changed, expired.
	Reason string `json:"reason,omitempty"`
	// Scope is what the member granted, space separated.
	Scope string `json:"scope,omitempty"`
}

// Authorization is the answer to a start: where the Workspace sends the member's browser. The URL is built by the
// bridge from the connection's pinned issuer, so it goes to the Workspace, which redirects; it is never part of a
// result a model reads.
type Authorization struct {
	URL string `json:"url"`
}

// Finish is what the Workspace hands over from the callback, after it has checked that the member who is logged in is
// the member who started: the three parameters of the redirect.
type Finish struct {
	Code  string `json:"code"`
	State string `json:"state"`
	Iss   string `json:"iss"`
	// Error is the callback's error parameter, if the authorization server refused: mapped to a fixed set of codes, and its
	// error_description, which the Workspace does not hand over, is never read.
	Error string `json:"error"`
}

// Error is an answer the service chooses: the HTTP status and a code from a fixed set, and for a refused authorization the
// reason. Nothing a third party said is in it.
type Error struct {
	Status int
	Code   string
	Reason string
}

func (e *Error) Error() string { return e.Code }

// Service is what B2 implements. who is the member the token named.
type Service interface {
	List(ctx context.Context, who auth.Subject) ([]ConnectionStatus, error)
	Start(ctx context.Context, who auth.Subject, connection string) (Authorization, error)
	Finish(ctx context.Context, who auth.Subject, connection string, f Finish) error
	Disconnect(ctx context.Context, who auth.Subject, connection string) error
	// ClientMetadata is the client metadata document of a connection that uses one (OAuth Client ID Metadata Document): its
	// content is the bridge's, built from its configuration, and the Workspace serves it at the connection's document address.
	// It holds nothing secret. An *Error with status 404 if the connection has none.
	ClientMetadata(connection string) (map[string]any, error)
}

// Authenticator verifies the exchanged token and returns the member (see the rule above).
type Authenticator interface {
	Authenticate(ctx context.Context, bearer string) (auth.Subject, error)
}

// Unimplemented is B1's Service and Authenticator: everything is ErrNotImplemented.
type Unimplemented struct{}

func (Unimplemented) List(context.Context, auth.Subject) ([]ConnectionStatus, error) {
	return nil, ErrNotImplemented
}
func (Unimplemented) Start(context.Context, auth.Subject, string) (Authorization, error) {
	return Authorization{}, ErrNotImplemented
}
func (Unimplemented) Finish(context.Context, auth.Subject, string, Finish) error {
	return ErrNotImplemented
}
func (Unimplemented) Disconnect(context.Context, auth.Subject, string) error {
	return ErrNotImplemented
}
func (Unimplemented) ClientMetadata(string) (map[string]any, error) { return nil, ErrNotImplemented }
func (Unimplemented) Authenticate(context.Context, string) (auth.Subject, error) {
	return auth.Subject{}, ErrNotImplemented
}

// Handler serves the API.
type Handler struct {
	Auth Authenticator
	Svc  Service
	mux  *http.ServeMux
}

// New builds the handler.
func New(a Authenticator, s Service) *Handler {
	h := &Handler{Auth: a, Svc: s, mux: http.NewServeMux()}
	h.route("GET /internal/v1/connections", func(w http.ResponseWriter, r *http.Request, who auth.Subject) error {
		list, err := h.Svc.List(r.Context(), who)
		if err == nil {
			reply(w, http.StatusOK, map[string]any{"connections": list})
		}
		return err
	})
	h.route("POST /internal/v1/connections/{id}/authorization", func(w http.ResponseWriter, r *http.Request, who auth.Subject) error {
		a, err := h.Svc.Start(r.Context(), who, r.PathValue("id"))
		if err == nil {
			reply(w, http.StatusOK, a)
		}
		return err
	})
	h.route("POST /internal/v1/connections/{id}/callback", func(w http.ResponseWriter, r *http.Request, who auth.Subject) error {
		var f Finish
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&f); err != nil {
			return errBadRequest
		}
		err := h.Svc.Finish(r.Context(), who, r.PathValue("id"), f)
		if err == nil {
			reply(w, http.StatusOK, map[string]string{"connection": r.PathValue("id"), "status": StatusConnected})
		}
		return err
	})
	h.route("DELETE /internal/v1/connections/{id}/grant", func(w http.ResponseWriter, r *http.Request, who auth.Subject) error {
		err := h.Svc.Disconnect(r.Context(), who, r.PathValue("id"))
		if err == nil {
			w.WriteHeader(http.StatusNoContent)
		}
		return err
	})
	// The client metadata document is public by design (the authorization server fetches it, through the Workspace, which serves
	// it): no token, nothing secret in it. Only the Workspace reaches this port in any case (the network policy).
	h.mux.HandleFunc("GET /internal/v1/connections/{id}/client-metadata", func(w http.ResponseWriter, r *http.Request) {
		doc, err := h.Svc.ClientMetadata(r.PathValue("id"))
		h.answer(w, err, func() { reply(w, http.StatusOK, doc) })
	})
	return h
}

var errBadRequest = errors.New("bad request")

func (h *Handler) route(pattern string, f func(http.ResponseWriter, *http.Request, auth.Subject) error) {
	h.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || strings.TrimSpace(bearer) == "" {
			unauthenticated(w)
			return
		}
		who, err := h.Auth.Authenticate(r.Context(), strings.TrimSpace(bearer))
		if err == nil && (who.Tenant == "" || who.Member == "") {
			err = ErrUnauthenticated
		}
		if err == nil {
			err = f(w, r, who)
		}
		h.answer(w, err, nil)
	})
}

// answer maps an error to its answer, or calls ok if there is none. Nothing of the error's text is sent: a code from a fixed set.
func (h *Handler) answer(w http.ResponseWriter, err error, ok func()) {
	var e *Error
	switch {
	case err == nil:
		if ok != nil {
			ok()
		}
	case errors.Is(err, ErrUnauthenticated):
		unauthenticated(w)
	case errors.Is(err, ErrNotImplemented):
		reply(w, http.StatusNotImplemented, map[string]string{"error": "not_implemented"})
	case errors.Is(err, errBadRequest):
		reply(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
	case errors.As(err, &e):
		body := map[string]string{"error": e.Code}
		if e.Reason != "" {
			body["reason"] = e.Reason
		}
		reply(w, e.Status, body)
	default:
		reply(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
	}
}

func unauthenticated(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	reply(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }
