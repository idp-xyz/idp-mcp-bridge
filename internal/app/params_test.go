package app

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"idp-mcp-bridge/internal/mcp/mcptest"
	"idp-mcp-bridge/internal/thirdparty"
)

func lists(r *rig) int {
	n := 0
	for _, q := range r.tp.Requests() {
		if q.Method == "tools/list" {
			n++
		}
	}
	return n
}

func paramHeadersOf(q thirdparty.Request) map[string]string {
	out := map[string]string{}
	for k, v := range q.Header {
		if strings.HasPrefix(k, "Mcp-Param-") {
			out[k] = v[0]
		}
	}
	return out
}

// ADR-0001 D34: the headers a tool declares are computed from the call's arguments and the definition the bridge listed, and the
// gateway's own Mcp-Param-* headers are not copied.
func TestTheHeadersAToolDeclaresAreComputedFromTheArgumentsAndTheGatewaysAreNotCopied(t *testing.T) {
	r := newRig(t, "", nil)
	w, m := mcptest.Post(r.h, Path("svc"), r.gw.CallBody(Audience(base, "svc"), "alice", "acme", "search", `{"region":"eu-west","limit":5,"flag":true,"query":"q","nested":{"a":"deep"}}`, ""),
		map[string]string{"Mcp-Param-Region": "from-the-gateway", "Mcp-Param-Evil": "x", "Mcp-Param-Query": "q"})
	if text(result(t, w, m)) != "ok search" {
		t.Fatalf("%s", w.Body)
	}
	got := paramHeadersOf(r.tp.Calls()[0])
	want := map[string]string{"Mcp-Param-Region": "eu-west", "Mcp-Param-Limit": "5", "Mcp-Param-Flag": "true", "Mcp-Param-Nested-A": "deep"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// the header allow-list of B1 stands: nothing else went out
	for name := range r.tp.Calls()[0].Header {
		if !allowedHeaders[name] && !strings.HasPrefix(name, "Mcp-Param-") {
			t.Errorf("header %s sent", name)
		}
	}
}

func TestAValueThatWouldInjectAHeaderLineReachesTheThirdPartyAsBase64AndAsNothingElse(t *testing.T) {
	r := newRig(t, "", nil)
	evil := "eu\r\nX-Evil: 1\r\nAuthorization: Bearer stolen"
	args, _ := jsonString(map[string]string{"region": evil})
	w, m := r.call("svc", "alice", "acme", "search", args)
	if text(result(t, w, m)) != "ok search" {
		t.Fatalf("%s", w.Body)
	}
	q := r.tp.Calls()[0]
	if q.Header.Get("X-Evil") != "" || q.Header.Get("Authorization") != "" {
		t.Fatalf("a header was injected: %v", q.Header)
	}
	v := q.Header.Get("Mcp-Param-Region")
	if !strings.HasPrefix(v, "=?base64?") {
		t.Fatalf("%q", v)
	}
	dec, _ := base64.StdEncoding.DecodeString(v[len("=?base64?") : len(v)-2])
	if string(dec) != evil {
		t.Fatalf("%q", dec)
	}
}

func TestAToolWhoseDefinitionIsUnknownOrInvalidGetsNoHeadersAndTheCallStillGoes(t *testing.T) {
	r := newRig(t, "", nil)
	// listed, with an invalid annotation: known, and without headers
	w, m := r.call("svc", "alice", "acme", "badparam", `{"x":1,"region":"eu"}`)
	if text(result(t, w, m)) != "ok badparam" {
		t.Fatalf("%s", w.Body)
	}
	// not in the listing at all
	w, m = r.call("svc", "alice", "acme", "nolisted", `{"region":"eu"}`)
	if text(result(t, w, m)) != "ok nolisted" {
		t.Fatalf("%s", w.Body)
	}
	for _, c := range r.tp.Calls() {
		if h := paramHeadersOf(c); len(h) != 0 {
			t.Errorf("%s: %v", c.Name, h)
		}
	}
	// a third party that cannot list: the call goes, without headers
	r2 := newRig(t, "", nil)
	r2.tp.Status = 503
	r2.call("svc", "alice", "acme", "search", `{"region":"eu"}`)
	r2.tp.Status = 0
	for _, c := range r2.tp.Calls() {
		if len(paramHeadersOf(c)) != 0 {
			t.Fatal("headers without a definition")
		}
	}
}

// The catalog is the last listing, whoever made it, refreshed on a miss and after its TTL, and a call cannot make the bridge list
// more than once in a while.
func TestTheCatalogIsRefreshedOnAMissAndAfterTheTTLAndNotMoreOftenThanTheMinimum(t *testing.T) {
	r := newRig(t, "", nil)
	call := func(tool string) { r.call("svc", "alice", "acme", tool, `{"region":"eu"}`) }
	call("search")
	if lists(r) != 1 {
		t.Fatalf("%d listings for the first call", lists(r))
	}
	call("search")
	call("search")
	if lists(r) != 1 || paramHeadersOf(r.tp.Calls()[2])["Mcp-Param-Region"] != "eu" {
		t.Fatalf("%d listings: a known tool makes none", lists(r))
	}
	// unknown tools: none within the minimum time of the last refresh, however many names are tried
	for i := 0; i < 5; i++ {
		call("nolisted")
	}
	if lists(r) != 1 {
		t.Fatalf("%d listings after five calls to an unknown tool", lists(r))
	}
	r.clock.Advance(31 * time.Second)
	call("nolisted")
	call("nolisted2")
	if lists(r) != 2 {
		t.Fatalf("%d listings: a miss after the minimum refreshes once", lists(r))
	}
	// the TTL
	r.clock.Advance(6 * time.Minute)
	call("search")
	if lists(r) != 3 {
		t.Fatalf("%d listings: a stale catalog is refreshed", lists(r))
	}
	// the gateway's own listing fills it too, so that no call has to
	r2 := newRig(t, "", nil)
	mcptest.Post(r2.h, Path("svc"), mcptest.ListBody(), nil)
	r2.call("svc", "alice", "acme", "search", `{"region":"eu"}`)
	if lists(r2) != 1 || paramHeadersOf(r2.tp.Calls()[0])["Mcp-Param-Region"] != "eu" {
		t.Fatalf("%d listings", lists(r2))
	}
}

func TestAnArgumentThatIsTooLongForItsHeaderRefusesTheCallAndNothingIsSent(t *testing.T) {
	r := newRig(t, "", nil)
	args, _ := jsonString(map[string]string{"region": strings.Repeat("x", 2000)})
	w, m := r.call("svc", "alice", "acme", "search", args)
	res := result(t, w, m)
	if res["isError"] != true || !strings.Contains(text(res), "too long") || len(r.tp.Calls()) != 0 {
		t.Fatalf("%s (%d calls)", w.Body, len(r.tp.Calls()))
	}
	// and it did not count against the third party
	r.tp.Status = 0
	if r.met == nil || !strings.Contains(r.metricsText(), `outcome="bad_request"`) {
		t.Fatalf("%s", r.metricsText())
	}
}

func TestTheRefreshOfTheCatalogUsesTheConnectionsLimitsAndTheBreaker(t *testing.T) {
	// a connection that is not closed does not list for a call
	r := newRig(t, "    breaker: {failures: 1, openSeconds: 30}", nil)
	mcptest.Post(r.h, Path("svc"), mcptest.ListBody(), nil)
	r.tp.Status = 503
	r.call("svc", "alice", "acme", "echo", `{}`) // opens it
	n := lists(r)
	r.clock.Advance(40 * time.Second) // the minimum has passed, the pause too: the trial is the call's, not a listing's
	r.tp.Status = 0
	r.call("svc", "alice", "acme", "nolisted", `{}`)
	if lists(r) != n {
		t.Fatalf("%d listings: the half-open trial was spent on a listing", lists(r)-n)
	}
	// a connection at its limit does not list for a call
	r2 := newRig(t, "    rateLimit: {windowSeconds: 60, connectionCalls: 1, memberCalls: 5}", nil)
	w, m := r2.call("svc", "alice", "acme", "search", `{"region":"eu"}`)
	if res := result(t, w, m); res["isError"] != nil || len(paramHeadersOf(r2.tp.Calls()[0])) != 0 || lists(r2) != 0 {
		t.Fatalf("%s %d", w.Body, lists(r2))
	}
	_ = http.StatusOK
}

func jsonString(v any) (string, error) { b, err := json.Marshal(v); return string(b), err }
