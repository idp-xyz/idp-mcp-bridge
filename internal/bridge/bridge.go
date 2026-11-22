// Package bridge is what one connection does with a call the gateway made (ADR-0001 D3 to D5, D8 to D14): it asks the
// token source for the member's token, applies the limits and the breaker, calls the third party through
// internal/upstream, and turns every way the call can end into an answer the model can act on, one audit line and one count.
package bridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"idp-mcp-bridge/internal/auth"
	"idp-mcp-bridge/internal/config"
	"idp-mcp-bridge/internal/guard"
	"idp-mcp-bridge/internal/mcp"
	"idp-mcp-bridge/internal/oauth"
	"idp-mcp-bridge/internal/upstream"
)

// AuthorizationRequiredKey is the key of structuredContent that tells the HOST (H1) and the Workspace that the member
// has to connect the service first. Its value holds the connection id and nothing else: never an address. The
// Workspace builds its own link to its own page; an address that came out of a tool result could be anyone's, and a model
// can be led to show it to the member (ADR-0001 D14).
const AuthorizationRequiredKey = upstream.Namespace + "authorizationRequired"

// Outcomes, the fixed set of the audit line and of the metrics.
const (
	OutcomeOK                    = "ok"
	OutcomeToolError             = "tool_error" // the third party's tool answered isError
	OutcomeRPCError              = "rpc_error"
	OutcomeAuthorizationRequired = "authorization_required"
	OutcomeTokenError            = "token_error"
	OutcomeRateLimited           = "rate_limited"
	OutcomeCircuitOpen           = "circuit_open"
	OutcomeUnreachable           = "unreachable"
	OutcomeBadResponse           = "bad_response"
	OutcomeTooLarge              = "result_too_large"
	OutcomeReverseRefused        = "reverse_refused"
	OutcomeRefused               = "refused" // the third party answered 4xx
	OutcomeFailed                = "failed"  // the third party answered 5xx
	OutcomeNotConfigured         = "not_configured"
	OutcomeBadRequest            = "bad_request"
	OutcomeCanceled              = "canceled"
)

// Deps are what every connection shares.
type Deps struct {
	Tokens   auth.TokenSource
	Reviewer auth.ReviewerSource
	Log      *slog.Logger
	Metrics  *Metrics
	Now      func() time.Time
}

// Connection is the runtime of one configured connection. It implements mcp.Backend.
type Connection struct {
	cfg     config.Connection
	client  *upstream.Client
	limiter *guard.Limiter
	breaker *guard.Breaker
	d       Deps
}

// New builds a connection from its configuration and the client that reaches the third party.
func New(cfg config.Connection, client *upstream.Client, d Deps) *Connection {
	if d.Now == nil {
		d.Now = time.Now
	}
	c := &Connection{cfg: cfg, client: client, d: d,
		limiter: guard.NewLimiter(cfg.RateLimit.Window(), cfg.RateLimit.ConnectionCalls, cfg.RateLimit.MemberCalls, d.Now),
		breaker: guard.NewBreaker(cfg.Breaker.Failures, cfg.Breaker.Open(), d.Now)}
	if d.Metrics != nil {
		d.Metrics.Gauge(cfg.ID, func() int { return int(c.breaker.State()) })
	}
	return c
}

// ID of the connection.
func (c *Connection) ID() string { return c.cfg.ID }

// Breaker is the connection's circuit breaker, for tests and metrics.
func (c *Connection) Breaker() *guard.Breaker { return c.breaker }

// short is the member as the audit line names them: a hash prefix, never the subject (idp-web ADR-0001 D4).
func short(owner string) string {
	if owner == "" {
		return ""
	}
	h := sha256.Sum256([]byte(owner))
	return hex.EncodeToString(h[:4])
}

type verdict struct {
	outcome string
	bytes   int64
}

func (c *Connection) record(tool string, who mcp.Caller, v verdict, start time.Time) {
	d := c.d.Now().Sub(start)
	if c.d.Metrics != nil {
		c.d.Metrics.Observe(c.cfg.ID, v.outcome, d, v.bytes)
	}
	if c.d.Log != nil {
		name := tool
		if len(name) > 64 {
			name = name[:64]
		}
		// What an audit line holds: which tool of which connection, whose tenant, a hash of the member, how it ended,
		// how much came back, how long it took. Never the arguments, the result or a token (ADR-0001 D17).
		c.d.Log.Info("audit", "tool", name, "connection", c.cfg.ID, "tenant", who.Tenant, "member", short(who.Owner()),
			"outcome", v.outcome, "bytes", v.bytes, "ms", d.Milliseconds())
	}
}

// toolError is a tool result with isError: what the model reads when a call did not produce an answer of the third party.
func toolError(text string, structured any) json.RawMessage {
	out := map[string]any{"resultType": "complete", "isError": true, "content": []map[string]any{{"type": "text", "text": text}}}
	if structured != nil {
		out["structuredContent"] = structured
	}
	b, _ := json.Marshal(out)
	return b
}

func (c *Connection) authorizationRequired() json.RawMessage {
	return toolError(fmt.Sprintf("The member has not connected %s yet, so this tool cannot be used. Ask the member to connect %s in the Workspace (the page of connected services), and to ask again once it is done. Do not call this tool again until they have.", c.cfg.Title, c.cfg.Title),
		map[string]any{AuthorizationRequiredKey: map[string]any{"connection": c.cfg.ID}})
}

func seconds(d time.Duration) int {
	n := int((d + time.Second - 1) / time.Second)
	if n < 1 {
		n = 1
	}
	return n
}

// ListTools forwards tools/list with the reviewer account's token (or none), for the gateway's registration, review and
// drift probes. There is no member in it.
func (c *Connection) ListTools(ctx context.Context) (json.RawMessage, error) {
	start := c.d.Now()
	var none mcp.Caller
	fail := func(outcome string, e *mcp.Error, bytes int64) (json.RawMessage, error) {
		c.record("tools/list", none, verdict{outcome, bytes}, start)
		return nil, e
	}
	if wait := c.limiter.AllowConnection(); wait > 0 {
		return fail(OutcomeRateLimited, &mcp.Error{Code: mcp.CodeInternal, Message: fmt.Sprintf("Too many requests to this connection; try again in %d seconds", seconds(wait)), Status: http.StatusTooManyRequests}, 0)
	}
	token := ""
	if c.cfg.Authorization.Mode == config.AuthOAuth {
		var err error
		if token, err = c.d.Reviewer.Token(ctx, c.cfg.ID); err != nil {
			return fail(OutcomeTokenError, &mcp.Error{Code: mcp.CodeInternal, Message: "The reviewer account's token is not available", Status: http.StatusBadGateway}, 0)
		}
	}
	if ok, wait := c.breaker.Allow(); !ok {
		return fail(OutcomeCircuitOpen, &mcp.Error{Code: mcp.CodeInternal, Message: fmt.Sprintf("The service is unavailable for now; try again in %d seconds", seconds(wait)), Status: http.StatusServiceUnavailable}, 0)
	}
	reply, err := c.client.ListTools(ctx, token)
	c.settle(ctx, err)
	if err != nil {
		outcome, why := classify(err)
		if errors.Is(err, upstream.ErrUnauthorized) {
			// the listing needs a credential this connection has no reviewer account for (B3)
			outcome, why = OutcomeNotConfigured, "the service wants a credential to list its tools, and no reviewer account is set up for it."
		}
		return fail(outcome, &mcp.Error{Code: mcp.CodeInternal, Message: "The service did not list its tools: " + why, Status: http.StatusBadGateway}, reply.Bytes)
	}
	c.record("tools/list", none, verdict{OutcomeOK, reply.Bytes}, start)
	return reply.Result, nil
}

// settle tells the breaker how a call that was allowed ended.
func (c *Connection) settle(ctx context.Context, err error) {
	switch {
	case ctx.Err() != nil:
		c.breaker.Abort() // the caller went away: that says nothing about the third party
	case upstream.Counts(err):
		c.breaker.Failure()
	default:
		c.breaker.Success()
	}
}

// CallTool forwards a tools/call on behalf of the member the gateway signed for. The order is the point (ADR-0001 D14):
// the token is asked for first, so a member who has none is answered with "authorization required" before anything
// is counted, queued or sent, and the third party hears nothing of the call.
func (c *Connection) CallTool(ctx context.Context, call mcp.Call) (json.RawMessage, error) {
	start := c.d.Now()
	end := func(outcome string, res json.RawMessage, bytes int64) (json.RawMessage, error) {
		c.record(call.Name, call.Caller, verdict{outcome, bytes}, start)
		return res, nil
	}
	if !upstream.ValidName(call.Name) {
		return end(OutcomeBadRequest, toolError("The tool name is not one that can be called.", nil), 0)
	}
	who := auth.Subject{Tenant: call.Caller.Tenant, Member: call.Caller.Subject}
	token := ""
	if c.cfg.Authorization.Mode == config.AuthOAuth {
		var err error
		token, err = c.d.Tokens.Token(ctx, who, c.cfg.ID)
		switch {
		case errors.Is(err, auth.ErrNoToken):
			return end(OutcomeAuthorizationRequired, c.authorizationRequired(), 0)
		case err != nil:
			return end(OutcomeTokenError, toolError("The credential for "+c.cfg.Title+" could not be read just now. Try again later.", nil), 0)
		}
	}
	if scope, wait := c.limiter.Allow(call.Caller.Owner()); wait > 0 {
		what := "You are calling"
		if scope == guard.ScopeConnection {
			what = "Everyone together is calling"
		}
		return end(OutcomeRateLimited, toolError(fmt.Sprintf("%s %s too often. Try again in %d seconds, and answer with what you already have.", what, c.cfg.Title, seconds(wait)), nil), 0)
	}
	if ok, wait := c.breaker.Allow(); !ok {
		return end(OutcomeCircuitOpen, toolError(fmt.Sprintf("%s is not answering at the moment, so the call was not made. Try again in %d seconds, or answer without it.", c.cfg.Title, seconds(wait)), nil), 0)
	}
	reply, err := c.client.CallTool(ctx, token, call.Name, call.Arguments, call.Progress)
	if errors.Is(err, upstream.ErrUnauthorized) && token != "" {
		// 401: the token is not good (expired, revoked). The source gets one chance to give a new one; if it has none the
		// member has to authorize again. Either way the answer of the first try is all the third party has heard.
		fresh, rerr := c.d.Tokens.Refresh(ctx, who, c.cfg.ID, token)
		switch {
		case errors.Is(rerr, auth.ErrNoToken):
			c.breaker.Success() // it answered
			return end(OutcomeAuthorizationRequired, c.authorizationRequired(), reply.Bytes)
		case rerr != nil:
			c.breaker.Success()
			return end(OutcomeTokenError, toolError("The credential for "+c.cfg.Title+" could not be renewed just now. Try again later.", nil), reply.Bytes)
		}
		reply, err = c.client.CallTool(ctx, fresh, call.Name, call.Arguments, call.Progress)
		if errors.Is(err, upstream.ErrUnauthorized) {
			c.breaker.Success()
			return end(OutcomeAuthorizationRequired, c.authorizationRequired(), reply.Bytes)
		}
	}
	c.settle(ctx, err)
	var se *upstream.StatusError
	if token != "" && errors.As(err, &se) && se.Status == http.StatusForbidden {
		// 403 with error="insufficient_scope": the token is good and asks too little (RFC 6750 section 3.1). The grant
		// remembers what is needed, and the member is asked to authorize again: the same marker as for no token, the
		// connection id and nothing else. A 403 without that error stays "the service refused".
		if ch := oauth.ParseChallenge(se.Challenge); ch["error"] == "insufficient_scope" {
			if up, ok := c.d.Tokens.(auth.StepUpper); ok {
				if uerr := up.InsufficientScope(ctx, who, c.cfg.ID, ch["scope"]); uerr == nil {
					return end(OutcomeAuthorizationRequired, c.authorizationRequired(), reply.Bytes)
				}
			}
		}
	}
	if err == nil {
		out := OutcomeOK
		if reply.IsError {
			out = OutcomeToolError
		}
		return end(out, reply.Result, reply.Bytes)
	}
	outcome, text := classify(err)
	if errors.Is(err, upstream.ErrUnauthorized) { // a connection that needs no token was asked for one
		outcome, text = OutcomeNotConfigured, "The service asked for a credential that this connection is not set up to give. Tell the operator."
	}
	if ctx.Err() != nil {
		outcome = OutcomeCanceled
	}
	return end(outcome, toolError(c.cfg.Title+": "+text, nil), reply.Bytes)
}

// classify maps an error of the upstream client to an outcome and a sentence for the model. The sentences are the
// bridge's words; what the third party said is quoted only for a JSON-RPC error, cut to 512 bytes.
func classify(err error) (string, string) {
	var rpc *upstream.RPCError
	var se *upstream.StatusError
	var le *upstream.LimitError
	var re *upstream.ReverseError
	switch {
	case errors.As(err, &re):
		return OutcomeReverseRefused, "the call was ended: " + re.Reason + "."
	case errors.As(err, &le):
		return OutcomeTooLarge, fmt.Sprintf("the answer is longer than the limit of %d bytes, so it was not delivered. Ask for less, or for a narrower part of it.", le.Limit)
	case errors.As(err, &rpc):
		return OutcomeRPCError, fmt.Sprintf("the service answered with an error (%d): %s", rpc.Code, rpc.Message)
	case errors.As(err, &se) && se.Status >= 500:
		return OutcomeFailed, fmt.Sprintf("the service failed (HTTP %d). The call may not have been carried out.", se.Status)
	case errors.As(err, &se):
		return OutcomeRefused, fmt.Sprintf("the service refused the call (HTTP %d).", se.Status)
	case errors.Is(err, upstream.ErrBadResponse), errors.Is(err, upstream.ErrRedirect):
		return OutcomeBadResponse, "the service's answer could not be used, so whether the call was carried out is not known."
	case errors.Is(err, upstream.ErrUnreachable):
		return OutcomeUnreachable, "the service did not answer. The call may not have been carried out."
	}
	return OutcomeFailed, "the call failed."
}
