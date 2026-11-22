package oauth

import (
	"context"
	"fmt"

	"idp-mcp-bridge/internal/grants"
	"idp-mcp-bridge/internal/sealer"
)

// RevokeMember is the operator's offboarding of a member (or of a member's one connection): each grant is revoked at its
// authorization server, best effort, if the connection is still configured and the server has a revocation endpoint, and is
// deleted whether or not that worked. It returns how many grants went.
func (s *Service) RevokeMember(ctx context.Context, tenant, member, connection string) (int, error) {
	gs, err := s.Store.ForMember(ctx, tenant, member)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, g := range gs {
		if connection != "" && g.Connection != connection {
			continue
		}
		s.Revoke(ctx, g)
		if err := s.Store.Delete(ctx, g.Key); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// RevokeConnection deletes every member's grant of a connection that the operator withdrew. Their tokens are not revoked at
// the authorization server: the grants are not listed by connection, and the connection is usually gone from the file by now.
func (s *Service) RevokeConnection(ctx context.Context, connection string) (int, error) {
	return s.Store.DeleteConnection(ctx, connection)
}

// Reseal rewrites every sealed value that is not under the current key (grants and dynamic registrations): it is opened with
// the key it names and sealed again with the current one. After it the old keys can leave the key file. Pending authorizations
// are not touched: they expire in ten minutes. It returns how many values were rewritten.
func Reseal(ctx context.Context, keys *sealer.Keys, st grants.Store) (int, error) {
	cur := keys.Current()
	old := func(sealed []byte) bool {
		if len(sealed) == 0 {
			return false
		}
		id, err := sealer.KeyID(sealed)
		return err != nil || id != cur
	}
	n, err := st.Reseal(ctx, func(g grants.Grant) (grants.Grant, bool, error) {
		if !old(g.SealedAccess) && !old(g.SealedRefresh) {
			return g, false, nil
		}
		for _, p := range []*[]byte{&g.SealedAccess, &g.SealedRefresh} {
			if len(*p) == 0 {
				continue
			}
			plain, err := keys.Open(*p, g.Key)
			if err != nil {
				return g, false, fmt.Errorf("a grant does not open (is the old key still in the key file?): %w", err)
			}
			if *p, err = keys.Seal(plain, g.Key); err != nil {
				return g, false, err
			}
		}
		return g, true, nil
	})
	if err != nil {
		return n, err
	}
	regs, err := st.Registrations(ctx)
	if err != nil {
		return n, err
	}
	for _, r := range regs {
		if !old(r.SealedSecret) {
			continue
		}
		k := grants.Key{Connection: r.Connection}
		plain, err := keys.Open(r.SealedSecret, k)
		if err != nil {
			return n, fmt.Errorf("a registration does not open: %w", err)
		}
		if r.SealedSecret, err = keys.Seal(plain, k); err != nil {
			return n, err
		}
		if err := st.PutRegistration(ctx, r); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
