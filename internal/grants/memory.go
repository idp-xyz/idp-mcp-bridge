package grants

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"
)

// Memory is a Store in memory, for the tests of what is above the store (and for nothing else: it is neither durable nor
// shared between replicas). It keeps the contract of the PostgreSQL one, Locked included.
type Memory struct {
	mu     sync.Mutex
	grants map[Key]Grant
	locks  map[Key]*sync.Mutex
	states map[string]State
	regs   map[[3]string]Registration
	unconf map[Key]time.Time
	locked map[int64]bool
}

// NewMemory makes an empty store.
func NewMemory() *Memory {
	return &Memory{grants: map[Key]Grant{}, locks: map[Key]*sync.Mutex{}, states: map[string]State{}, regs: map[[3]string]Registration{}, unconf: map[Key]time.Time{}, locked: map[int64]bool{}}
}

func clone(g Grant) Grant {
	g.SealedAccess = append([]byte(nil), g.SealedAccess...)
	g.SealedRefresh = append([]byte(nil), g.SealedRefresh...)
	return g
}

func (m *Memory) Get(_ context.Context, k Key) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[k]
	if !ok {
		return Grant{}, ErrNotFound
	}
	return clone(g), nil
}

func (m *Memory) Put(_ context.Context, g Grant) error {
	m.mu.Lock()
	m.grants[g.Key] = clone(g)
	m.mu.Unlock()
	return nil
}

func (m *Memory) Delete(_ context.Context, k Key) error {
	m.mu.Lock()
	delete(m.grants, k)
	m.mu.Unlock()
	return nil
}

func (m *Memory) DeleteMember(_ context.Context, tenant, member string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k := range m.grants {
		if !k.Reviewer && k.Tenant == tenant && k.Member == member {
			delete(m.grants, k)
			n++
		}
	}
	return n, nil
}

func (m *Memory) DeleteConnection(_ context.Context, connection string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k := range m.grants {
		if k.Connection == connection {
			delete(m.grants, k)
			n++
		}
	}
	return n, nil
}

func (m *Memory) ForMember(_ context.Context, tenant, member string) ([]Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Grant
	for k, g := range m.grants {
		if !k.Reviewer && k.Tenant == tenant && k.Member == member {
			out = append(out, clone(g))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Connection < out[j].Connection })
	return out, nil
}

func (m *Memory) lock(k Key) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locks[k] == nil {
		m.locks[k] = &sync.Mutex{}
	}
	return m.locks[k]
}

func (m *Memory) Locked(ctx context.Context, k Key, fn func(Grant) (Grant, Action, error)) error {
	l := m.lock(k)
	l.Lock()
	defer l.Unlock()
	g, err := m.Get(ctx, k)
	if err != nil {
		return err
	}
	ng, act, err := fn(g)
	if err != nil {
		return err
	}
	switch act {
	case Update:
		ng.Key = k
		return m.Put(ctx, ng)
	case Delete:
		return m.Delete(ctx, k)
	}
	return nil
}

func (m *Memory) Reseal(ctx context.Context, fn func(Grant) (Grant, bool, error)) (int, error) {
	m.mu.Lock()
	var keys []Key
	for k := range m.grants {
		keys = append(keys, k)
	}
	m.mu.Unlock()
	n := 0
	for _, k := range keys {
		err := m.Locked(ctx, k, func(g Grant) (Grant, Action, error) {
			ng, changed, err := fn(g)
			if err != nil || !changed {
				return g, Keep, err
			}
			n++
			return ng, Update, nil
		})
		if err != nil && err != ErrNotFound {
			return n, err
		}
	}
	return n, nil
}

func (m *Memory) PutState(_ context.Context, s State) error {
	m.mu.Lock()
	m.states[string(s.Hash)] = s
	m.mu.Unlock()
	return nil
}

func (m *Memory) TakeState(_ context.Context, hash []byte, tenant, member string) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.states[string(hash)]
	if !ok || s.Tenant != tenant || s.Member != member || !bytes.Equal(s.Hash, hash) {
		return State{}, ErrNotFound
	}
	delete(m.states, string(hash))
	return s, nil
}

func (m *Memory) SweepStates(_ context.Context, cutoff time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for h, s := range m.states {
		if s.Expires.Before(cutoff) {
			delete(m.states, h)
			n++
		}
	}
	return n, nil
}

// States is how many authorizations are pending, for tests.
func (m *Memory) States() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.states)
}

func (m *Memory) GetRegistration(_ context.Context, connection, issuer, redirectURI string) (Registration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.regs[[3]string{connection, issuer, redirectURI}]
	if !ok {
		return Registration{}, ErrNotFound
	}
	return r, nil
}

func (m *Memory) PutRegistration(_ context.Context, r Registration) error {
	m.mu.Lock()
	m.regs[[3]string{r.Connection, r.Issuer, r.RedirectURI}] = r
	m.mu.Unlock()
	return nil
}

var _ Store = (*Memory)(nil)

func (m *Memory) Registrations(_ context.Context) ([]Registration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Registration
	for _, r := range m.regs {
		out = append(out, r)
	}
	return out, nil
}

func (m *Memory) DeleteMemberStates(_ context.Context, tenant, member string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for h, s := range m.states {
		if s.Tenant == tenant && s.Member == member {
			delete(m.states, h)
			n++
		}
	}
	return n, nil
}

func (m *Memory) Members(_ context.Context) ([][2]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[[2]string]bool{}
	var out [][2]string
	for k := range m.grants {
		if k.Reviewer {
			continue
		}
		if p := [2]string{k.Tenant, k.Member}; !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0]+"\x00"+out[i][1] < out[j][0]+"\x00"+out[j][1] })
	return out, nil
}

func (m *Memory) MarkAuthorizerLeft(_ context.Context, authorizedBy string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, g := range m.grants {
		if k.Reviewer && g.AuthorizedBy == authorizedBy {
			g.AuthorizerLeft = true
			m.grants[k] = g
			n++
		}
	}
	return n, nil
}

func (m *Memory) PutUnconfirmed(_ context.Context, k Key, at time.Time) error {
	m.mu.Lock()
	m.unconf[k] = at
	m.mu.Unlock()
	return nil
}

func (m *Memory) ClearUnconfirmed(_ context.Context, k Key) error {
	m.mu.Lock()
	delete(m.unconf, k)
	m.mu.Unlock()
	return nil
}

func (m *Memory) Unconfirmed(_ context.Context, tenant, member string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.unconf {
		if k.Tenant == tenant && k.Member == member {
			out = append(out, k.Connection)
		}
	}
	sort.Strings(out)
	return out, nil
}

// TryLock is shared by every user of this Memory, which is what a test of "one replica at a time" needs.
func (m *Memory) TryLock(_ context.Context, id int64) (func(), bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked[id] {
		return nil, false, nil
	}
	m.locked[id] = true
	return func() { m.mu.Lock(); delete(m.locked, id); m.mu.Unlock() }, true, nil
}

func (m *Memory) Authorizers(_ context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for k, g := range m.grants {
		if k.Reviewer && !g.AuthorizerLeft && g.AuthorizedBy != "" && !seen[g.AuthorizedBy] {
			seen[g.AuthorizedBy] = true
			out = append(out, g.AuthorizedBy)
		}
	}
	sort.Strings(out)
	return out, nil
}
