// Package auth declares where the bridge gets the credential it presents to a third party (ADR-0001 D13). B1 declares
// the two sources and implements both as "no token"; B2 (OAuth, per member) implements TokenSource, B3 the reviewer
// account.
//
// The rule that keeps one member's token from being used for another: the Subject a TokenSource is asked about is made
// from the caller the gateway signed (internal/mcp, assertion.go) and from nothing else. It is never a tool argument,
// a header or a field of _meta, so a member cannot name another member, and a model that is told to cannot either.
package auth

import (
	"context"
	"errors"
)

// ErrNoToken: there is no usable token for this member on this connection: never authorized, expired and not
// refreshable, revoked, or the member's grant was deleted. The call is then answered with "authorization required" and
// the third party is not called (ADR-0001 D14).
var ErrNoToken = errors.New("no token for this member")

// Subject is a member as the gateway's assertion names them.
type Subject struct {
	Tenant string
	Member string
}

// TokenSource gives the token to call a connection with on behalf of a member. A token it returns is an access token
// for this connection's resource, never logged and never in an error message.
type TokenSource interface {
	// Token returns the member's current access token, refreshing it first if it has expired and a refresh token
	// allows. ErrNoToken if there is none. Any other error is a failure of the source (the store is down): the call
	// fails and the third party is not called either.
	Token(ctx context.Context, who Subject, connection string) (string, error)
	// Refresh is asked after the third party refused rejected (HTTP 401): it returns a new access token, or
	// ErrNoToken if the member has to authorize again. It is called at most once per call.
	Refresh(ctx context.Context, who Subject, connection string, rejected string) (string, error)
}

// StepUpper is what a TokenSource may also do: take note that the third party asked for more scope than the member's grant has
// (HTTP 403 with WWW-Authenticate error="insufficient_scope", RFC 6750 section 3.1). The grant is then not used until the
// member authorizes again, and that authorization asks for the union of what was granted and what is now needed.
type StepUpper interface {
	InsufficientScope(ctx context.Context, who Subject, connection string, scope string) error
}

// ReviewerSource gives the token for the calls that have no member: tools/list for the gateway's registration, review
// and drift probes (plan section 2, item 8). It is an account the operator authorized for this connection, used for
// discovery and probes only and never for a member's call.
type ReviewerSource interface {
	// Token returns the reviewer account's token, or "" for a connection that needs none.
	Token(ctx context.Context, connection string) (string, error)
}

// NoTokens is B1's TokenSource: nobody has a token.
type NoTokens struct{}

func (NoTokens) Token(context.Context, Subject, string) (string, error) { return "", ErrNoToken }
func (NoTokens) Refresh(context.Context, Subject, string, string) (string, error) {
	return "", ErrNoToken
}

// NoReviewer is B1's ReviewerSource: discovery goes out without a token, which is right for a connection that
// needs none.
type NoReviewer struct{}

func (NoReviewer) Token(context.Context, string) (string, error) { return "", nil }
