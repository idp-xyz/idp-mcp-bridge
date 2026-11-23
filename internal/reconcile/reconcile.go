// Package reconcile is the backstop for members who leave without anyone telling the bridge (ADR-0001 D39): every round it asks the
// directory about each member who holds grants and offboards those who are gone, disabled or moved to another tenant. The route
// that tells the bridge in real time is the first line; this is what catches what it missed.
//
// The rules: only a clear answer acts (unknown, which is every error, does nothing and is tried again next round); a round in
// which too many members would leave does nothing at all (the brake: a directory that is wrong or empty must not be able to wipe
// every member's authorizations), unless an operator, having looked, forces it; one replica reconciles at a time.
package reconcile

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"idp-mcp-bridge/internal/directory"
	"idp-mcp-bridge/internal/grants"
	"idp-mcp-bridge/internal/oauth"
)

// Defaults and the brake's numbers.
const (
	DefaultInterval = 15 * time.Minute
	lockID          = 72592 // the advisory lock of a round
	// BrakeMin and BrakeNumerator/BrakeDenominator: if at least BrakeMin members, and more than 20% of those seen in the round, are
	// to be offboarded, the round does nothing.
	BrakeMin         = 5
	brakePercent     = 20
	defaultLookupTTL = 10 * time.Second
)

// Offboarder does what the route does (oauth.Service).
type Offboarder interface {
	Offboard(ctx context.Context, req oauth.OffboardRequest) (oauth.OffboardResult, error)
	AuthorizerLeft(ctx context.Context, tenant, member, reason, source string) (int, error)
}

// Reconciler runs the rounds.
type Reconciler struct {
	Store    grants.Store
	Dir      directory.Directory
	Off      Offboarder
	Log      *slog.Logger
	Counters oauth.Counters
	Interval time.Duration
	// LookupTimeout bounds one lookup (default 10 s).
	LookupTimeout time.Duration
}

// Report is what a round did.
type Report struct {
	Members, Present, Unknown int
	Leaving                   int
	Offboarded                int
	Braked                    bool
	// Busy: another replica holds the round.
	Busy bool
}

func (r *Reconciler) inc(name string, n int, labels ...string) {
	if r.Counters != nil && n > 0 {
		r.Counters.Inc(name, n, labels...)
	}
}

func reasonOf(s directory.Status) string {
	switch s {
	case directory.Deleted:
		return oauth.ReasonUserDeleted
	case directory.Disabled:
		return oauth.ReasonUserDisabled
	}
	return oauth.ReasonTenantChanged
}

// Round runs one round. force goes past the brake and nothing else.
func (r *Reconciler) Round(ctx context.Context, force bool) (Report, error) {
	var rep Report
	release, ok, err := r.Store.TryLock(ctx, lockID)
	if err != nil {
		return rep, err
	}
	if !ok {
		rep.Busy = true
		r.inc("reconcile_rounds_total", 1, "result", "busy")
		return rep, nil
	}
	defer release()
	members, err := r.Store.Members(ctx)
	if err != nil {
		return rep, err
	}
	// The people a round looks up: the members who hold grants, and the operators who authorized a reviewer account (D40), who may hold
	// none of their own. Each counts once, in the brake's denominator and numerator alike.
	holds := map[[2]string]bool{}
	for _, m := range members {
		holds[m] = true
	}
	authorizers, err := r.Store.Authorizers(ctx)
	if err != nil {
		return rep, err
	}
	for _, a := range authorizers {
		t, m, ok := strings.Cut(a, "/") // as stored: tenant, "/", member
		if !ok || t == "" || m == "" {
			if r.Log != nil {
				r.Log.Warn("a reviewer grant has an authorizer that is not tenant/member: skipped")
			}
			continue
		}
		if !holds[[2]string{t, m}] {
			members = append(members, [2]string{t, m})
		}
	}
	rep.Members = len(members)
	type leaver struct {
		tenant, member string
		status         directory.Status
	}
	var leaving []leaver
	timeout := r.LookupTimeout
	if timeout == 0 {
		timeout = defaultLookupTTL
	}
	for _, m := range members {
		lctx, cancel := context.WithTimeout(ctx, timeout)
		st, lerr := r.Dir.Lookup(lctx, m[0], m[1])
		cancel()
		if lerr != nil {
			st = directory.Unknown // an error is never an answer
			if r.Log != nil {
				r.Log.Warn("the directory could not tell", "tenant", m[0]) // not the error: it may name an address
			}
		}
		r.inc("reconcile_lookups_total", 1, "status", st.String())
		switch st {
		case directory.Present:
			rep.Present++
		case directory.Unknown:
			rep.Unknown++
		default:
			leaving = append(leaving, leaver{m[0], m[1], st})
		}
	}
	rep.Leaving = len(leaving)
	if !force && rep.Leaving >= BrakeMin && rep.Leaving*100 > brakePercent*rep.Members {
		rep.Braked = true
		r.inc("reconcile_rounds_total", 1, "result", "braked")
		r.inc("reconcile_brake_total", 1)
		if r.Log != nil {
			r.Log.Error("reconciliation brake: too many members would be offboarded, nothing was done this round; check the directory, then run `reconcile --now --force`",
				"leaving", rep.Leaving, "members", rep.Members)
		}
		return rep, nil
	}
	for _, l := range leaving {
		reason := reasonOf(l.status)
		if !holds[[2]string{l.tenant, l.member}] { // authorized a reviewer account, holds nothing: only the account is marked
			if _, err := r.Off.AuthorizerLeft(ctx, l.tenant, l.member, reason, "reconcile"); err != nil {
				if r.Log != nil {
					r.Log.Error("a reviewer account could not be marked", "tenant", l.tenant)
				}
				continue
			}
			rep.Offboarded++
			r.inc("reconcile_offboarded_total", 1, "reason", reason)
			continue
		}
		if _, err := r.Off.Offboard(ctx, oauth.OffboardRequest{Tenant: l.tenant, Member: l.member, Reason: reason, Source: "reconcile"}); err != nil {
			if r.Log != nil {
				r.Log.Error("a member could not be offboarded", "tenant", l.tenant)
			}
			continue
		}
		rep.Offboarded++
		r.inc("reconcile_offboarded_total", 1, "reason", reason)
	}
	r.inc("reconcile_rounds_total", 1, "result", "done")
	if r.Log != nil {
		r.Log.Info("reconciliation round", "members", rep.Members, "present", rep.Present, "unknown", rep.Unknown, "leaving", rep.Leaving, "offboarded", rep.Offboarded, "forced", force)
	}
	return rep, nil
}

// Run runs a round every Interval until ctx ends; an Interval of zero runs none.
func (r *Reconciler) Run(ctx context.Context) {
	if r.Interval <= 0 {
		return
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := r.Round(ctx, false); err != nil && r.Log != nil {
				r.Log.Error("a reconciliation round failed")
			}
		}
	}
}
