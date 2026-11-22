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
}

// NewMemory makes an empty store.
func NewMemory() *Memory {
	return &Memory{grants: map[Key]Grant{}, locks: map[Key]*sync.Mutex{}, states: map[string]State{}, regs: map[[3]string]Registration{}}
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
		if k.Tenant == tenant && k.Member == member {
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
		if k.Tenant == tenant && k.Member == member {
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
