package bridge

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Metrics counts what the bridge did, by connection and outcome, in Prometheus text (idp-web ADR-0001 D24's form).
// There is no label that comes from a caller: the outcomes are a fixed set and the connections are configured ones, so
// no member and no tool name can grow the table.
type Metrics struct {
	mu     sync.Mutex
	counts map[[2]string]int64
	nanos  map[string]int64
	bytes  map[string]int64
	states map[string]func() int
	named  map[string]int64
}

// NewMetrics makes an empty set.
func NewMetrics() *Metrics {
	return &Metrics{counts: map[[2]string]int64{}, nanos: map[string]int64{}, bytes: map[string]int64{}, states: map[string]func() int{}, named: map[string]int64{}}
}

// Observe counts one call (or listing) of a connection.
func (m *Metrics) Observe(connection, outcome string, d time.Duration, bytes int64) {
	m.mu.Lock()
	m.counts[[2]string{connection, outcome}]++
	m.nanos[connection] += d.Nanoseconds()
	m.bytes[connection] += bytes
	m.mu.Unlock()
}

// Inc counts something that is not a call: offboarding, reconciliation (labels are name, value pairs, from fixed sets).
func (m *Metrics) Inc(name string, n int, labels ...string) {
	var b strings.Builder
	b.WriteString("idp_bridge_" + name)
	if len(labels) > 1 {
		b.WriteString("{")
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, "%s=%q", labels[i], labels[i+1])
		}
		b.WriteString("}")
	}
	m.mu.Lock()
	m.named[b.String()] += int64(n)
	m.mu.Unlock()
}

// Gauge registers the breaker state of a connection (0 closed, 1 open, 2 half-open), read at each scrape.
func (m *Metrics) Gauge(connection string, state func() int) {
	m.mu.Lock()
	m.states[connection] = state
	m.mu.Unlock()
}

// Write writes the metrics, sorted so that two scrapes of the same state read the same.
func (m *Metrics) Write(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([][2]string, 0, len(m.counts))
	for k := range m.counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	fmt.Fprintln(w, "# TYPE idp_bridge_calls_total counter")
	for _, k := range keys {
		fmt.Fprintf(w, "idp_bridge_calls_total{connection=%q,outcome=%q} %d\n", k[0], k[1], m.counts[k])
	}
	names := func(in map[string]int64) []string {
		out := make([]string, 0, len(in))
		for k := range in {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	fmt.Fprintln(w, "# TYPE idp_bridge_call_seconds_total counter")
	for _, c := range names(m.nanos) {
		fmt.Fprintf(w, "idp_bridge_call_seconds_total{connection=%q} %g\n", c, float64(m.nanos[c])/1e9)
	}
	fmt.Fprintln(w, "# TYPE idp_bridge_result_bytes_total counter")
	for _, c := range names(m.bytes) {
		fmt.Fprintf(w, "idp_bridge_result_bytes_total{connection=%q} %d\n", c, m.bytes[c])
	}
	ns := make([]string, 0, len(m.named))
	for k := range m.named {
		ns = append(ns, k)
	}
	sort.Strings(ns)
	for _, k := range ns {
		fmt.Fprintf(w, "%s %d\n", k, m.named[k])
	}
	fmt.Fprintln(w, "# TYPE idp_bridge_breaker_state gauge")
	gs := make([]string, 0, len(m.states))
	for k := range m.states {
		gs = append(gs, k)
	}
	sort.Strings(gs)
	for _, c := range gs {
		fmt.Fprintf(w, "idp_bridge_breaker_state{connection=%q} %d\n", c, m.states[c]())
	}
}
