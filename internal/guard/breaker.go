package guard

import (
	"sync"
	"time"
)

// State of a breaker.
type State int

const (
	Closed   State = iota // calls go through
	Open                  // calls are refused until the pause is over
	HalfOpen              // one trial call is in flight; the others are refused
)

func (s State) String() string { return [...]string{"closed", "open", "half-open"}[s] }

// Breaker is the circuit breaker of one connection: it opens after Failures consecutive failures, refuses calls for
// Pause, then lets exactly one call through; that call's outcome closes it or opens it again for another pause. What
// counts as a failure is the caller's decision (upstream.Counts): the third party did not answer, or did not answer
// with an answer. A third party that answers "no" is well.
//
// It protects the third party from a pile of calls it cannot serve, the members' runs from waiting out timeouts one
// call after another, and the bridge's connections.
type Breaker struct {
	Failures int
	Pause    time.Duration
	Now      func() time.Time

	mu       sync.Mutex
	state    State
	failures int
	until    time.Time
}

// NewBreaker makes a closed breaker; now may be nil.
func NewBreaker(failures int, pause time.Duration, now func() time.Time) *Breaker {
	if now == nil {
		now = time.Now
	}
	return &Breaker{Failures: failures, Pause: pause, Now: now}
}

// Allow says whether a call may go out. If not it returns how long until the breaker may let one through. A call
// that was allowed must be followed by exactly one of Success, Failure or Abort.
func (b *Breaker) Allow() (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case Open:
		if now := b.Now(); now.Before(b.until) {
			return false, b.until.Sub(now)
		}
		b.state = HalfOpen // this call is the trial
		return true, 0
	case HalfOpen:
		return false, b.Pause // the trial is in flight
	}
	return true, 0
}

// Success: the call was answered.
func (b *Breaker) Success() {
	b.mu.Lock()
	b.state, b.failures = Closed, 0
	b.mu.Unlock()
}

// Failure: the call was not answered.
func (b *Breaker) Failure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	if b.state == HalfOpen || b.failures >= b.Failures {
		b.state = Open
		b.until = b.Now().Add(b.Pause)
	}
}

// Abort: the call ended for a reason that says nothing about the third party (the caller went away). A trial that is
// aborted is given back, so that the next call is the trial.
func (b *Breaker) Abort() {
	b.mu.Lock()
	if b.state == HalfOpen {
		b.state = Open
		b.until = b.Now() // may be tried again at once
	}
	b.mu.Unlock()
}

// State is for metrics and logs.
func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}
