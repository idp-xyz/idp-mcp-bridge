// Package directory is the bridge's view of the identity system, as far as it needs one: is a member who has grants still a member
// (ADR-0001 D39). It is an interface because the identity system the platform ends up with is not chosen: the only adapter is
// keycloakdev, for development and tests, and nothing outside this directory (and the one place main selects it) knows Keycloak.
package directory

import "context"

// Status of a member in the identity system.
type Status int

// The answers of a lookup. Unknown is what any error, timeout, missing permission or answer that does not look like a user gives:
// the reconciliation never acts on it.
const (
	Unknown  Status = iota
	Present         // still a member of the tenant
	Disabled        // the account is disabled
	Deleted         // the account does not exist
	Moved           // the account exists and belongs to another tenant now
)

func (s Status) String() string {
	return [...]string{"unknown", "present", "disabled", "deleted", "moved"}[s]
}

// Directory looks a member up. A non-nil error always comes with Unknown.
type Directory interface {
	Lookup(ctx context.Context, tenant, member string) (Status, error)
}
