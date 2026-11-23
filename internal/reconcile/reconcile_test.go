package reconcile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"idp-mcp-bridge/internal/directory"
	"idp-mcp-bridge/internal/grants"
	"idp-mcp-bridge/internal/grants/pgtest"
	"idp-mcp-bridge/internal/oauth"
)

// fakeDir answers from a table; a member that is not in it is present.
type fakeDir struct {
	mu      sync.Mutex
	answers map[[2]string]directory.Status
	errs    map[[2]string]error
	block   chan struct{} // if set, every lookup waits for it
	asked   int
}

func (d *fakeDir) Lookup(ctx context.Context, tenant, member string) (directory.Status, error) {
	d.mu.Lock()
	d.asked++
	b := d.block
	st, e := directory.Present, d.errs[[2]string{tenant, member}]
	if v, ok := d.answers[[2]string{tenant, member}]; ok {
		st = v
	}
	d.mu.Unlock()
	if b != nil {
		select {
		case <-b:
		case <-ctx.Done():
			return directory.Unknown, ctx.Err()
		}
	}
	if e != nil {
		return directory.Unknown, e
	}
	return st, nil
}

type recOff struct {
	mu    sync.Mutex
	reqs  []oauth.OffboardRequest
	marks []string // tenant/member whose reviewer accounts were marked, with the reason
	fail  map[string]bool
}

func (o *recOff) AuthorizerLeft(_ context.Context, tenant, member, reason, source string) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.marks = append(o.marks, tenant+"/"+member+":"+reason+":"+source)
	return 1, nil
}

func (o *recOff) Offboard(_ context.Context, r oauth.OffboardRequest) (oauth.OffboardResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail[r.Member] {
		return oauth.OffboardResult{}, errors.New("boom")
	}
	o.reqs = append(o.reqs, r)
	return oauth.OffboardResult{GrantsRemoved: 1}, nil
}

type counts struct {
	mu sync.Mutex
	m  map[string]int
}

func (c *counts) Inc(name string, n int, labels ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]int{}
	}
	c.m[name+fmt.Sprint(labels)] += n
}

func seed(t *testing.T, st grants.Store, n int) [][2]string {
	t.Helper()
	var out [][2]string
	for i := 0; i < n; i++ {
		m := [2]string{"acme", fmt.Sprintf("m%02d", i)}
		out = append(out, m)
		for _, conn := range []string{"notes", "crm"} { // two grants each: a member counts once
			if err := st.Put(context.Background(), grants.Grant{Key: grants.Key{Tenant: m[0], Member: m[1], Connection: conn}, SealedAccess: []byte("x"), Issuer: "i"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	// a reviewer account is not a member
	_ = st.Put(context.Background(), grants.Grant{Key: grants.Key{Connection: "notes", Reviewer: true}, SealedAccess: []byte("x"), Issuer: "i", AuthorizedBy: "acme/m00"})
	return out
}

func newRec(st grants.Store, d directory.Directory) (*Reconciler, *recOff, *counts, *bytes.Buffer) {
	off, c, buf := &recOff{}, &counts{}, &bytes.Buffer{}
	return &Reconciler{Store: st, Dir: d, Off: off, Counters: c, Log: slog.New(slog.NewJSONHandler(buf, nil)), LookupTimeout: 200 * time.Millisecond}, off, c, buf
}

func TestAMemberWhoIsDeletedDisabledOrMovedIsOffboardedWithTheReasonOfTheLookupAndNobodyElseIs(t *testing.T) {
	st := grants.NewMemory()
	ms := seed(t, st, 30)
	d := &fakeDir{answers: map[[2]string]directory.Status{ms[0]: directory.Deleted, ms[1]: directory.Disabled, ms[2]: directory.Moved}}
	r, off, c, _ := newRec(st, d)
	rep, err := r.Round(context.Background(), false)
	if err != nil || rep.Members != 30 || rep.Leaving != 3 || rep.Offboarded != 3 || rep.Present != 27 || rep.Braked {
		t.Fatalf("%+v %v", rep, err)
	}
	got := map[string]string{}
	for _, q := range off.reqs {
		if q.Source != "reconcile" || q.Tenant != "acme" {
			t.Errorf("%+v", q)
		}
		got[q.Member] = q.Reason
	}
	if got[ms[0][1]] != "user_deleted" || got[ms[1][1]] != "user_disabled" || got[ms[2][1]] != "tenant_changed" || len(got) != 3 {
		t.Fatalf("%v", got)
	}
	if c.m["reconcile_lookups_total[status present]"] != 27 || c.m["reconcile_offboarded_total[reason user_deleted]"] != 1 {
		t.Fatalf("%v", c.m)
	}
}

// Only a clear answer acts.
func TestAnythingThatIsNotAClearAnswerDoesNothing(t *testing.T) {
	st := grants.NewMemory()
	ms := seed(t, st, 10)
	d := &fakeDir{errs: map[[2]string]error{ms[0]: errors.New("timeout"), ms[1]: errors.New("HTTP 500"), ms[2]: errors.New("HTTP 403"), ms[3]: errors.New("not a user")},
		answers: map[[2]string]directory.Status{ms[4]: directory.Unknown}}
	r, off, c, buf := newRec(st, d)
	rep, err := r.Round(context.Background(), false)
	if err != nil || rep.Unknown != 5 || rep.Offboarded != 0 || len(off.reqs) != 0 || rep.Braked {
		t.Fatalf("%+v %v", rep, err)
	}
	if c.m["reconcile_lookups_total[status unknown]"] != 5 || !strings.Contains(buf.String(), "could not tell") {
		t.Fatalf("%v %s", c.m, buf)
	}
	if strings.Contains(buf.String(), "HTTP 500") || strings.Contains(buf.String(), "timeout") {
		t.Fatal("the directory's error text is in the log")
	}
	// a directory that is down altogether: nothing is done and the brake is not what held it
	d2 := &fakeDir{errs: map[[2]string]error{}}
	for _, m := range ms {
		d2.errs[m] = errors.New("unreachable")
	}
	r2, off2, _, _ := newRec(st, d2)
	if rep, _ := r2.Round(context.Background(), false); rep.Unknown != 10 || rep.Braked || len(off2.reqs) != 0 {
		t.Fatalf("%+v", rep)
	}
	// a lookup that takes too long is unknown too
	d3 := &fakeDir{block: make(chan struct{})}
	r3, off3, _, _ := newRec(st, d3)
	r3.LookupTimeout = 20 * time.Millisecond
	if rep, _ := r3.Round(context.Background(), false); rep.Unknown != 10 || len(off3.reqs) != 0 {
		t.Fatalf("%+v", rep)
	}
}

func TestTheSafetyBrakeHoldsARoundInWhichMoreThanAFifthAndAtLeastFiveWouldGoUnlessForced(t *testing.T) {
	for _, c := range []struct {
		members, leaving int
		braked           bool
	}{
		{5, 4, false},  // 80%, but fewer than five
		{25, 5, false}, // exactly 20%
		{24, 5, true},  // more than 20%
		{25, 6, true},  // 24%
		{100, 20, false},
		{100, 21, true},
		{10, 10, true}, // the directory says everyone left
	} {
		st := grants.NewMemory()
		ms := seed(t, st, c.members)
		d := &fakeDir{answers: map[[2]string]directory.Status{}}
		for i := 0; i < c.leaving; i++ {
			d.answers[ms[i]] = directory.Deleted
		}
		r, off, cnt, buf := newRec(st, d)
		rep, err := r.Round(context.Background(), false)
		if err != nil || rep.Braked != c.braked || (c.braked && len(off.reqs) != 0) || (!c.braked && len(off.reqs) != c.leaving) {
			t.Errorf("%+v: %+v %v (%d offboarded)", c, rep, err, len(off.reqs))
		}
		if c.braked {
			if cnt.m["reconcile_brake_total[]"] != 1 || !strings.Contains(buf.String(), "reconciliation brake") || !strings.Contains(buf.String(), `"level":"ERROR"`) {
				t.Errorf("%+v: no alert: %v %s", c, cnt.m, buf)
			}
			// forced, after an operator's check: the round goes through
			rep, _ = r.Round(context.Background(), true)
			if rep.Braked || len(off.reqs) != c.leaving {
				t.Errorf("%+v forced: %+v", c, rep)
			}
		}
	}
}

func TestOneMemberThatCannotBeOffboardedDoesNotStopTheRestAndANoOpIntervalRunsNothing(t *testing.T) {
	st := grants.NewMemory()
	ms := seed(t, st, 30)
	d := &fakeDir{answers: map[[2]string]directory.Status{ms[0]: directory.Deleted, ms[1]: directory.Deleted}}
	r, off, _, buf := newRec(st, d)
	off.fail = map[string]bool{ms[0][1]: true}
	rep, _ := r.Round(context.Background(), false)
	if rep.Offboarded != 1 || len(off.reqs) != 1 || off.reqs[0].Member != ms[1][1] || !strings.Contains(buf.String(), "could not be offboarded") {
		t.Fatalf("%+v", rep)
	}
	// Interval 0 is off; a small one runs rounds until the context ends
	r.Interval = 0
	done := make(chan struct{})
	go func() { r.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a zero interval did not return")
	}
	r.Interval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	go func() { r.Run(ctx); close(make(chan struct{})) }()
	time.Sleep(120 * time.Millisecond)
	cancel()
	d.mu.Lock()
	asked := d.asked
	d.mu.Unlock()
	if asked < 60 {
		t.Fatalf("%d lookups: no further round ran", asked)
	}
}

// One replica reconciles at a time: while one round holds the lock another is told it is busy, and does nothing.
func TestOnlyOneReplicaReconcilesAtATime(t *testing.T) {
	stores := map[string]func() (grants.Store, grants.Store){
		"memory": func() (grants.Store, grants.Store) { m := grants.NewMemory(); return m, m },
	}
	if pgtest.Enabled() {
		stores["postgres"] = func() (grants.Store, grants.Store) {
			_, url := pgtest.Scratch(t)
			open := func() grants.Store {
				s, err := grants.Open(context.Background(), url)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(s.Close)
				return s
			}
			return open(), open()
		}
	}
	for name, mk := range stores {
		t.Run(name, func(t *testing.T) {
			s1, s2 := mk()
			seed(t, s1, 5)
			gate := make(chan struct{})
			d1 := &fakeDir{block: gate}
			r1, _, _, _ := newRec(s1, d1)
			r1.LookupTimeout = 5 * time.Second
			r2, off2, _, _ := newRec(s2, &fakeDir{answers: map[[2]string]directory.Status{{"acme", "m00"}: directory.Deleted}})
			started := make(chan Report)
			go func() { rep, _ := r1.Round(context.Background(), false); started <- rep }()
			deadline := time.Now().Add(3 * time.Second)
			for {
				d1.mu.Lock()
				n := d1.asked
				d1.mu.Unlock()
				if n > 0 || time.Now().After(deadline) {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			rep, err := r2.Round(context.Background(), false)
			if err != nil || !rep.Busy || len(off2.reqs) != 0 {
				t.Fatalf("the second replica ran while the first held the round: %+v %v", rep, err)
			}
			close(gate)
			if first := <-started; first.Busy {
				t.Fatal("the first was busy")
			}
			// the lock is released: the second may run now
			if rep, _ = r2.Round(context.Background(), false); rep.Busy || len(off2.reqs) != 1 {
				t.Fatalf("%+v", rep)
			}
		})
	}
}

func addReviewer(t *testing.T, st grants.Store, conn, authorizedBy string) {
	t.Helper()
	if err := st.Put(context.Background(), grants.Grant{Key: grants.Key{Connection: conn, Reviewer: true}, SealedAccess: []byte("x"), Issuer: "i", AuthorizedBy: authorizedBy}); err != nil {
		t.Fatal(err)
	}
}

// ADR-0001 D40: an operator who authorized a reviewer account and holds no grant of his own is looked up too, and only the account is
// marked when he leaves.
func TestAnAuthorizerWithNoMemberGrantsIsLookedUpAndWhenHeLeavesOnlyTheAccountIsMarked(t *testing.T) {
	for _, status := range []directory.Status{directory.Deleted, directory.Disabled, directory.Moved} {
		st := grants.NewMemory()
		seed(t, st, 30)
		addReviewer(t, st, "github", "acme/ops") // ops holds no member grant
		d := &fakeDir{answers: map[[2]string]directory.Status{{"acme", "ops"}: status}}
		r, off, _, _ := newRec(st, d)
		rep, err := r.Round(context.Background(), false)
		if err != nil || rep.Members != 31 || rep.Leaving != 1 || rep.Offboarded != 1 {
			t.Fatalf("%v: %+v %v", status, rep, err)
		}
		if len(off.reqs) != 0 || len(off.marks) != 1 || off.marks[0] != "acme/ops:"+reasonOf(status)+":reconcile" {
			t.Fatalf("%v: offboarded %v, marked %v", status, off.reqs, off.marks)
		}
	}
	// present and unknown: nothing
	for _, d := range []*fakeDir{{}, {errs: map[[2]string]error{{"acme", "ops"}: errors.New("down")}}} {
		st := grants.NewMemory()
		seed(t, st, 30)
		addReviewer(t, st, "github", "acme/ops")
		r, off, _, _ := newRec(st, d)
		rep, _ := r.Round(context.Background(), false)
		if len(off.reqs) != 0 || len(off.marks) != 0 || rep.Members != 31 {
			t.Fatalf("%+v %v", rep, off.marks)
		}
	}
}

func TestAnAuthorizerWhoAlsoHoldsMemberGrantsIsOffboardedOnceAndNotCountedTwice(t *testing.T) {
	st := grants.NewMemory()
	ms := seed(t, st, 30) // seed's reviewer account was authorized by acme/m00
	d := &fakeDir{answers: map[[2]string]directory.Status{ms[0]: directory.Deleted}}
	r, off, _, _ := newRec(st, d)
	rep, _ := r.Round(context.Background(), false)
	if rep.Members != 30 || rep.Leaving != 1 || len(off.reqs) != 1 || len(off.marks) != 0 {
		t.Fatalf("%+v %v %v", rep, off.reqs, off.marks)
	}
	// an account already marked is not looked up again, so the alert is raised once
	st2 := grants.NewMemory()
	seed(t, st2, 30)
	addReviewer(t, st2, "github", "acme/ops")
	_, _ = st2.MarkAuthorizerLeft(context.Background(), "acme/ops")
	d2 := &fakeDir{}
	r2, _, _, _ := newRec(st2, d2)
	rep, _ = r2.Round(context.Background(), false)
	if rep.Members != 30 {
		t.Fatalf("a marked account's authorizer was looked up: %+v", rep)
	}
}

// Authorizers count in the brake like any member: a mass false "left" must not mark every reviewer account.
func TestTheBrakeCountsAuthorizersWithNoMemberGrantsToo(t *testing.T) {
	st := grants.NewMemory()
	seed(t, st, 6)
	for i := 0; i < 6; i++ { // six operators, each the authorizer of one account, none holding member grants
		addReviewer(t, st, fmt.Sprintf("svc%d", i), fmt.Sprintf("acme/op%d", i))
	}
	d := &fakeDir{answers: map[[2]string]directory.Status{}}
	for i := 0; i < 6; i++ {
		d.answers[[2]string{"acme", fmt.Sprintf("op%d", i)}] = directory.Deleted
	}
	r, off, cnt, _ := newRec(st, d)
	rep, _ := r.Round(context.Background(), false)
	// 6 of 12 would leave: nothing is marked
	if !rep.Braked || rep.Members != 12 || len(off.marks) != 0 || cnt.m["reconcile_brake_total[]"] != 1 {
		t.Fatalf("%+v %v", rep, off.marks)
	}
	if rep, _ = r.Round(context.Background(), true); rep.Braked || len(off.marks) != 6 {
		t.Fatalf("forced: %+v %v", rep, off.marks)
	}
}

func TestAnAuthorizerThatIsNotTenantSlashMemberIsSkippedAndLogged(t *testing.T) {
	st := grants.NewMemory()
	seed(t, st, 10)
	for i, bad := range []string{"nobody", "/x", "x/", "a/b"} {
		addReviewer(t, st, fmt.Sprintf("c%d", i), bad)
	}
	r, off, _, buf := newRec(st, &fakeDir{answers: map[[2]string]directory.Status{{"a", "b"}: directory.Deleted}})
	rep, _ := r.Round(context.Background(), false)
	if rep.Members != 11 || strings.Count(buf.String(), "not tenant/member") != 3 || len(off.marks) != 1 || off.marks[0] != "a/b:user_deleted:reconcile" {
		t.Fatalf("%+v %v %s", rep, off.marks, buf)
	}
}
