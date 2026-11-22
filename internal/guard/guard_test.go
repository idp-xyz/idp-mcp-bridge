package guard

import (
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestTheLimiterSlidesAndDoesNotCountARefusal(t *testing.T) {
	c := &clock{time.Unix(1000, 0)}
	l := NewLimiter(60*time.Second, 100, 2, c.now)
	for i := 0; i < 2; i++ {
		if s, w := l.Allow("a"); s != "" || w != 0 {
			t.Fatalf("call %d: %s %v", i, s, w)
		}
		c.t = c.t.Add(10 * time.Second)
	}
	// refused, with the time until the oldest call leaves the window
	if s, w := l.Allow("a"); s != ScopeMember || w != 40*time.Second {
		t.Fatalf("%s %v", s, w)
	}
	// a refusal is not recorded: when the first call has left the window there is room for one, not for none
	c.t = c.t.Add(41 * time.Second)
	if s, _ := l.Allow("a"); s != "" {
		t.Fatalf("refusals were counted: %s", s)
	}
	if s, _ := l.Allow("a"); s != ScopeMember {
		t.Fatalf("the window holds two calls: %s", s)
	}
	// another member has a window of their own
	if s, _ := l.Allow("b"); s != "" {
		t.Fatalf("b: %s", s)
	}
}

func TestTheConnectionLimitIsSharedAndAMemberRefusedForItDoesNotUseTheirOwn(t *testing.T) {
	c := &clock{time.Unix(1000, 0)}
	l := NewLimiter(60*time.Second, 3, 3, c.now)
	l.Allow("a")
	l.Allow("b")
	l.Allow("c")
	if s, _ := l.Allow("d"); s != ScopeConnection {
		t.Fatalf("%s", s)
	}
	// d's refusal was not recorded against d, who has a full allowance once the window has passed
	c.t = c.t.Add(61 * time.Second)
	for i := 0; i < 3; i++ {
		if s, _ := l.Allow("d"); s != "" {
			t.Fatalf("d, call %d: %s", i, s)
		}
	}
	// a request without a member counts for the connection only
	c.t = c.t.Add(61 * time.Second)
	for i := 0; i < 3; i++ {
		if w := l.AllowConnection(); w != 0 {
			t.Fatal("refused early")
		}
	}
	if w := l.AllowConnection(); w <= 0 {
		t.Fatal("not refused")
	}
	if s, _ := l.Allow("a"); s != ScopeConnection {
		t.Fatalf("%s", s)
	}
}

func TestTheLimiterTableIsBounded(t *testing.T) {
	c := &clock{time.Unix(1000, 0)}
	l := NewLimiter(time.Second, 1<<30, 5, c.now)
	for i := 0; i < maxTable+500; i++ {
		l.Allow(string(rune(i)) + "x" + time.Duration(i).String())
		if i%1000 == 0 {
			c.t = c.t.Add(2 * time.Second)
		}
	}
	c.t = c.t.Add(2 * time.Second)
	l.Allow("last")
	if n := len(l.members); n > maxTable+1000 {
		t.Fatalf("%d members kept", n)
	}
}

func TestTheLimiterIsSafeForConcurrentUse(t *testing.T) {
	l := NewLimiter(time.Minute, 50, 1000, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s, _ := l.Allow("m"); s == "" {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 50 {
		t.Fatalf("%d calls allowed, want exactly 50", allowed)
	}
}

func TestTheBreakerOpensAfterConsecutiveFailuresOnly(t *testing.T) {
	c := &clock{time.Unix(1000, 0)}
	b := NewBreaker(3, 30*time.Second, c.now)
	for i := 0; i < 2; i++ {
		b.Allow()
		b.Failure()
	}
	b.Allow()
	b.Success() // a success in between: the count starts again
	for i := 0; i < 2; i++ {
		if ok, _ := b.Allow(); !ok {
			t.Fatal("opened early")
		}
		b.Failure()
	}
	if ok, _ := b.Allow(); !ok || b.State() != Closed {
		t.Fatalf("%v", b.State())
	}
	b.Failure()
	if ok, wait := b.Allow(); ok || wait != 30*time.Second || b.State() != Open {
		t.Fatalf("%v %v", ok, wait)
	}
}

func TestTheBreakerLetsOneTrialThroughAfterThePauseAndDecidesByIt(t *testing.T) {
	c := &clock{time.Unix(1000, 0)}
	b := NewBreaker(1, 30*time.Second, c.now)
	b.Allow()
	b.Failure()
	c.t = c.t.Add(29 * time.Second)
	if ok, wait := b.Allow(); ok || wait != time.Second {
		t.Fatalf("%v %v", ok, wait)
	}
	c.t = c.t.Add(2 * time.Second)
	if ok, _ := b.Allow(); !ok || b.State() != HalfOpen {
		t.Fatal("no trial")
	}
	if ok, _ := b.Allow(); ok {
		t.Fatal("a second call went through while the trial is in flight")
	}
	b.Failure() // the trial failed: open for another pause
	if ok, wait := b.Allow(); ok || wait != 30*time.Second {
		t.Fatalf("%v %v", ok, wait)
	}
	c.t = c.t.Add(31 * time.Second)
	b.Allow()
	b.Success()
	if ok, _ := b.Allow(); !ok || b.State() != Closed {
		t.Fatalf("%v", b.State())
	}
}

func TestAnAbortedTrialIsGivenBack(t *testing.T) {
	c := &clock{time.Unix(1000, 0)}
	b := NewBreaker(1, 30*time.Second, c.now)
	b.Allow()
	b.Failure()
	c.t = c.t.Add(31 * time.Second)
	b.Allow()
	b.Abort()
	if ok, _ := b.Allow(); !ok {
		t.Fatal("the breaker is stuck half open after the caller went away")
	}
}
