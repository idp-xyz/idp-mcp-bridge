// Package grants is the store of the members' grants (ADR-0001 D15, D24): for each (tenant, member, connection) the
// encrypted tokens OAuth obtained, the authorizations that are under way, and the clients registered dynamically. Two
// implementations: PostgreSQL (pg.go, what runs) and memory (memory.go, for tests of everything above it).
//
// The boundary is drawn so that the store never sees a token: it keeps what a Sealer made of it. A database that is read by
// someone it should not be, or a backup that leaks, then holds ciphertext, and the key is in a Secret the database does not
// have.
package grants

import (
	"context"
	"errors"
	"time"
)

// Reasons a grant needs the member to authorize again.
const ReasonInsufficientScope = "insufficient_scope"

// ErrNotFound: there is no such row.
var ErrNotFound = errors.New("not found")

// Key identifies a grant. The tenant and the member are Keycloak's (and the gateway's), the connection is a configured id; a
// grant is never found by anything else.
type Key struct {
	Tenant, Member, Connection string
	// Reviewer marks the connection's reviewer grant (ADR-0001 D33): then Tenant and Member are empty, there is one per connection,
	// and it is never a member's own grant, not even of the operator who authorized it: it is part of the key and of what the seal
	// binds.
	Reviewer bool
}

// Grant is a member's authorization of one connection, as stored.
type Grant struct {
	Key
	// SealedAccess and SealedRefresh are what a Sealer made of the tokens; the id of the key is inside them. The refresh token
	// may be absent (the authorization server issued none).
	SealedAccess  []byte
	SealedRefresh []byte
	// AccessExpires is when the access token stops being good (zero: the server did not say).
	AccessExpires time.Time
	// Issuer is the authorization server that issued them, as pinned in the configuration at the time: a grant whose issuer is
	// no longer the connection's is not used.
	Issuer string
	// Scope is what was granted. NeededScope is what the third party asked for with insufficient_scope (the union of the
	// granted scope and the challenge's): the next authorization asks for it. ReauthReason, when set, says why the grant is
	// not used until the member authorizes again (ReasonInsufficientScope).
	Scope        string
	NeededScope  string
	ReauthReason string
	CreatedAt    time.Time
	RefreshedAt  time.Time
	// AuthorizedBy is, for a reviewer grant, the tenant/member of the operator who authorized it.
	AuthorizedBy string
	// AuthorizerLeft marks a reviewer grant whose authorizer has left (ADR-0001 D40): kept, and shown as such.
	AuthorizerLeft bool
}

// State is an authorization that is under way: what the callback needs to finish it and to check who finishes it. Keyed by
// the SHA-256 of the state parameter, so that a copy of the table does not give out a state that is still good.
type State struct {
	Hash []byte
	Key
	// SealedVerifier is the PKCE code verifier, sealed for Key.
	SealedVerifier []byte
	Issuer         string
	RedirectURI    string
	Scope          string
	ClientID       string
	Resource       string
	Expires        time.Time
}

// Registration is a client registered dynamically at an authorization server (opt-in, ADR-0001 D22), one per connection,
// issuer and redirect address.
type Registration struct {
	Connection, Issuer, RedirectURI string
	ClientID                        string
	SealedSecret                    []byte // may be absent: a public client
	AuthMethod                      string
}

// Action is what a Locked function wants done with the row it was shown.
type Action int

// What a Locked function may ask for.
const (
	Keep   Action = iota // leave the row as it is
	Update               // write the grant the function returned
	Delete               // remove the row
)

// Store keeps grants. Every method is safe for concurrent use, across replicas for the PostgreSQL implementation.
type Store interface {
	Get(ctx context.Context, k Key) (Grant, error)
	Put(ctx context.Context, g Grant) error
	// Delete removes one grant (the member disconnects). Removing one that is not there is not an error.
	Delete(ctx context.Context, k Key) error
	// DeleteMember removes every grant of a member (the member left the tenant) and DeleteConnection every grant of a
	// connection (the operator withdrew it); both return how many rows went.
	DeleteMember(ctx context.Context, tenant, member string) (int, error)
	DeleteConnection(ctx context.Context, connection string) (int, error)
	// ForMember lists a member's grants; the tokens in them stay sealed.
	ForMember(ctx context.Context, tenant, member string) ([]Grant, error)
	// Locked shows fn the grant with its row locked until fn returns: for as long as it runs, no other caller, on any replica,
	// is shown the same grant (they wait, then see what fn left). ErrNotFound if there is no grant. An error of fn leaves the
	// row as it was.
	Locked(ctx context.Context, k Key, fn func(Grant) (Grant, Action, error)) error
	// Reseal shows fn every grant, one at a time and locked, for the operator's re-sealing under the current key; it returns
	// how many were rewritten.
	Reseal(ctx context.Context, fn func(Grant) (Grant, bool, error)) (int, error)

	// PutState stores a pending authorization. TakeState removes and returns it in one statement, only if it belongs to the
	// tenant and member given (a state presented by someone else is not consumed and is not told apart from one that never
	// was); ErrNotFound otherwise. An expired state is returned and removed all the same: the caller judges the time.
	PutState(ctx context.Context, s State) error
	TakeState(ctx context.Context, hash []byte, tenant, member string) (State, error)
	// SweepStates removes the states that expired before cutoff.
	SweepStates(ctx context.Context, cutoff time.Time) (int, error)

	// DeleteMemberStates removes a member's pending authorizations (the member left).
	DeleteMemberStates(ctx context.Context, tenant, member string) (int, error)
	// Members lists the distinct (tenant, member) of the members' own grants (not the reviewer accounts'), for the reconciliation.
	Members(ctx context.Context) ([][2]string, error)
	// Authorizers lists the distinct authorized_by (tenant/member, as stored) of the reviewer grants not yet marked: the operators whose
	// departure matters although they may hold no member grant of their own.
	Authorizers(ctx context.Context) ([]string, error)
	// MarkAuthorizerLeft marks the reviewer grants authorized by authorizedBy (tenant/member) and returns how many.
	MarkAuthorizerLeft(ctx context.Context, authorizedBy string) (int, error)
	// PutUnconfirmed records that a member's revocation on a connection could not be confirmed; ClearUnconfirmed removes the record
	// (the member connected again); Unconfirmed lists a member's connections that have one.
	PutUnconfirmed(ctx context.Context, k Key, at time.Time) error
	ClearUnconfirmed(ctx context.Context, k Key) error
	Unconfirmed(ctx context.Context, tenant, member string) ([]string, error)
	// TryLock takes the lock named id if no one holds it, anywhere (PostgreSQL: an advisory lock, so one replica at a time); ok is
	// false if someone does. release gives it back.
	TryLock(ctx context.Context, id int64) (release func(), ok bool, err error)

	GetRegistration(ctx context.Context, connection, issuer, redirectURI string) (Registration, error)
	PutRegistration(ctx context.Context, r Registration) error
	// Registrations lists them all, for the operator's re-sealing.
	Registrations(ctx context.Context) ([]Registration, error)
}

// Sealer encrypts and decrypts a secret (AES-GCM, internal/sealer). The additional data binds the ciphertext to its owner:
// a sealed value copied to another member's row does not open.
type Sealer interface {
	Seal(plaintext []byte, owner Key) ([]byte, error)
	Open(sealed []byte, owner Key) ([]byte, error)
}
