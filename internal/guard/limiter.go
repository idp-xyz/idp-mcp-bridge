// Package guard holds the two protections of a connection that are about the bridge's own load and the third party's
// health: the rate limits and the circuit breaker (ADR-0001 D12, D13).
package guard

import (
	"sync"
	"time"
)

// Scope of a refusal.
const (
	ScopeConnection = "connection"
	ScopeMember     = "member"
)

// maxTable bounds the per-member table.
const maxTable = 10000

// Limiter is a sliding window in memory, per replica (idp-web ADR-0001 D22): at most Connection calls of all members
// together and at most Member calls of one member in any Window. It cannot count per run: the gateway's assertion
// carries no run number, and the HOST's step limit bounds a run.
//
// With N replicas a member can make up to N times the window's calls; the third party's own limits are the bound that is exact.
type Limiter struct {
	Window     time.Duration
	Connection int
	Member     int
	Now        func() time.Time

	mu      sync.Mutex
	all     []time.Time
	members map[string][]time.Time
}

// NewLimiter makes a limiter; now may be nil.
func NewLimiter(window time.Duration, connection, member int, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{Window: window, Connection: connection, Member: member, Now: now, members: map[string][]time.Time{}}
}

func (l *Limiter) trim(h []time.Time, now time.Time) []time.Time {
	i := 0
	for i < len(h) && now.Sub(h[i]) >= l.Window {
		i++
	}
	return h[i:]
}

// Allow records a call by member and returns 0, or the scope that is over its limit and the time to wait (the call is
// then not recorded in either scope: a refusal does not use up the member's allowance, and a member refused by their own
// limit does not use up the connection's).
func (l *Limiter) Allow(member string) (string, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now()
	l.all = l.trim(l.all, now)
	mine := l.trim(l.members[member], now)
	if len(mine) >= l.Member {
		l.members[member] = mine
		return ScopeMember, mine[0].Add(l.Window).Sub(now)
	}
	if len(l.all) >= l.Connection {
		l.members[member] = mine
		return ScopeConnection, l.all[0].Add(l.Window).Sub(now)
	}
	if len(l.members) > maxTable { // bound the table: drop the members whose calls are all out of the window
		for k, hs := range l.members {
			if len(hs) == 0 || now.Sub(hs[len(hs)-1]) >= l.Window {
				delete(l.members, k)
			}
		}
	}
	l.members[member] = append(mine, now)
	l.all = append(l.all, now)
	return "", 0
}

// AllowConnection is Allow for a request that has no member (the listing of tools for the gateway's probes): only the
// connection's window is asked and recorded.
func (l *Limiter) AllowConnection() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now()
	l.all = l.trim(l.all, now)
	if len(l.all) >= l.Connection {
		return l.all[0].Add(l.Window).Sub(now)
	}
	l.all = append(l.all, now)
	return 0
}
