package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"idp-mcp-bridge/internal/auth"
	"idp-mcp-bridge/internal/bridge"
	"idp-mcp-bridge/internal/config"
	"idp-mcp-bridge/internal/egress"
	"idp-mcp-bridge/internal/mcp/mcptest"
	"idp-mcp-bridge/internal/thirdparty"
)

func TestAConnectionWithoutAuthorizationWorksEndToEnd(t *testing.T) {
	r := newRig(t, "", nil)
	w, m := r.call("svc", "alice", "acme", "echo", `{"text":"hello"}`)
	res := result(t, w, m)
	if text(res) != "hello" || res["resultType"] != "complete" || res["isError"] != nil {
		t.Fatalf("%v", res)
	}
	calls := r.tp.Calls()
	if len(calls) != 1 || calls[0].Name != "echo" || string(calls[0].Params["arguments"]) != `{"text":"hello"}` {
		t.Fatalf("the third party received %+v", calls)
	}
	if calls[0].Header.Get("Authorization") != "" {
		t.Fatal("a connection that needs no token sent one")
	}
	// the listing works the same way, without a member
	w, m = mcptest.Post(r.h, Path("svc"), mcptest.ListBody(), nil)
	tools := result(t, w, m)["tools"].([]any)
	if len(tools) == 0 || tools[0].(map[string]any)["name"] != "echo" {
		t.Fatalf("%v", m)
	}
	// and discovery is answered by the bridge: the third party hears nothing of it
	before := len(r.tp.Requests())
	w, m = mcptest.Post(r.h, Path("svc"), `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{`+mcptest.Meta+`}}}`, nil)
	if result(t, w, m)["supportedVersions"].([]any)[0] != "2026-07-28" || len(r.tp.Requests()) != before {
		t.Fatalf("discovery: %v", m)
	}
}

func TestAForgedOrMissingAssertionIsRefusedBeforeAnythingLeaves(t *testing.T) {
	r := newRig(t, "", nil)
	other := mcptest.New()
	good := r.gw.CallBody(Audience(base, "svc"), "alice", "acme", "echo", `{"text":"x"}`, "")
	cases := map[string]string{
		"no assertion": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"},"_meta":{` + mcptest.Meta + `}}}`,
		"an unsigned caller in _meta": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"},"_meta":{` + mcptest.Meta +
			`,"io.idp.telos/caller":{"subject":"alice","tenant":"acme","roles":[]}}}}`,
		"signed by another key":                 other.CallBody(Audience(base, "svc"), "alice", "acme", "echo", `{"text":"x"}`, ""),
		"made for another connection":           r.gw.CallBody(Audience(base, "needs-auth"), "alice", "acme", "echo", `{"text":"x"}`, ""),
		"made for another address":              r.gw.CallBody("http://elsewhere:1/mcp/svc", "alice", "acme", "echo", `{"text":"x"}`, ""),
		"arguments changed after the signature": strings.Replace(good, `"text":"x"`, `"text":"y"`, 2),
		"another tool than the one signed":      strings.Replace(good, `"name":"echo"`, `"name":"whoami"`, 1),
		"an assertion that is not a JWS":        `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{},"_meta":{` + mcptest.Meta + `,"io.idp.telos/caller-assertion":"nope"}}}`,
	}
	for name, body := range cases {
		w, m := mcptest.Post(r.h, Path("svc"), body, nil)
		if w.Code != http.StatusForbidden || m["error"] == nil || m["result"] != nil {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	// the same assertion twice: the second is a replay
	if w, _ := mcptest.Post(r.h, Path("svc"), good, nil); w.Code != 200 {
		t.Fatalf("the genuine call: %d", w.Code)
	}
	if w, _ := mcptest.Post(r.h, Path("svc"), good, nil); w.Code != http.StatusForbidden {
		t.Errorf("a replayed assertion: %d", w.Code)
	}
	if n := len(r.tp.Calls()); n != 1 {
		t.Fatalf("the third party received %d calls; only the genuine one should have gone out", n)
	}
	if got := r.tok.Asked(); len(got) != 0 {
		t.Fatalf("a token was looked up for a refused call: %v", got)
	}
}

// the headers the bridge may send: nothing of the caller, nothing that traces, nothing that was only a client's
var allowedHeaders = map[string]bool{"Accept": true, "Content-Type": true, "Content-Length": true, "Mcp-Method": true, "Mcp-Name": true,
	"Mcp-Protocol-Version": true, "User-Agent": true, "Accept-Encoding": true}

func TestTheThirdPartyReceivesNoIdentityNoAssertionNoCustomMetaNoTraceHeaders(t *testing.T) {
	r := newRig(t, "", nil)
	params := map[string]json.RawMessage{
		"name": json.RawMessage(`"echo"`), "arguments": json.RawMessage(`{"text":"hello"}`),
		"task": json.RawMessage(`{"ttl":1}`), "inputResponses": json.RawMessage(`{"a":{}}`), "requestState": json.RawMessage(`"s"`), "invented": json.RawMessage(`"x"`),
	}
	extra := `"progressToken":"p-1","io.modelcontextprotocol/clientInfo":{"name":"idp-host","version":"9"},"traceparent":"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",` +
		`"tracestate":"a=b","baggage":"k=v","io.idp.telos/caller":{"subject":"alice"},"x-custom":"c"`
	body := r.gw.CallBodyParams(Audience(base, "svc"), "alice", "acme", params, extra)
	w, m := mcptest.Post(r.h, Path("svc"), body, map[string]string{
		"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", "tracestate": "a=b", "baggage": "k=v",
		"Authorization": "Bearer the-members-keycloak-token", "Cookie": "s=1", "Mcp-Param-Region": "eu", "X-Forwarded-For": "10.1.2.3",
		"X-Request-Id": "r1", "Mcp-Name": "echo", "Forwarded": "for=10.1.2.3"})
	if result(t, w, m); len(r.tp.Calls()) != 1 {
		t.Fatalf("%d calls", len(r.tp.Calls()))
	}
	got := r.tp.Calls()[0]
	// the body: the name, the arguments and the envelope, in which the progress token is the only thing of the caller's
	keys := map[string]bool{}
	for k := range got.Params {
		keys[k] = true
	}
	if len(keys) != 3 || !keys["name"] || !keys["arguments"] || !keys["_meta"] {
		t.Fatalf("params sent: %v", keys)
	}
	var meta map[string]json.RawMessage
	_ = json.Unmarshal(got.Params["_meta"], &meta)
	want := map[string]string{"io.modelcontextprotocol/protocolVersion": `"2026-07-28"`, "io.modelcontextprotocol/clientCapabilities": `{}`, "progressToken": `"p-1"`}
	if len(meta) != len(want) {
		t.Fatalf("_meta sent: %s", got.Params["_meta"])
	}
	for k, v := range want {
		if string(meta[k]) != v {
			t.Errorf("_meta[%s] = %s", k, meta[k])
		}
	}
	// the headers: only the allow-list, and no value that came from the caller
	for name := range got.Header {
		if !allowedHeaders[name] {
			t.Errorf("header %s sent to the third party: %v", name, got.Header[name])
		}
	}
	if got.Header.Get("Mcp-Method") != "tools/call" || got.Header.Get("Mcp-Name") != "echo" || got.Header.Get("MCP-Protocol-Version") != "2026-07-28" {
		t.Errorf("the transport headers: %v", got.Header)
	}
	// nothing of the member anywhere in what was sent, headers included
	all := string(got.Body) + asJSON(got.Header)
	for _, secret := range []string{"alice", "acme", "eyJ", "idp-host", "caller", "keycloak", "10.1.2.3", "traceparent", "0af7651916cd"} {
		if strings.Contains(strings.ToLower(all), strings.ToLower(secret)) {
			t.Errorf("what the third party received contains %q: %s", secret, all)
		}
	}
}

func TestAnInvalidProgressTokenIsNotForwardedAndNoneMeansNone(t *testing.T) {
	r := newRig(t, "", nil)
	for _, extra := range []string{`"progressToken":{"a":1}`, `"progressToken":1.5`, ""} {
		w, m := mcptest.Post(r.h, Path("svc"), r.gw.CallBody(Audience(base, "svc"), "alice", "acme", "echo", `{}`, extra), nil)
		result(t, w, m)
	}
	for _, c := range r.tp.Calls() {
		if strings.Contains(string(c.Params["_meta"]), "progressToken") {
			t.Errorf("sent %s", c.Params["_meta"])
		}
	}
}

func TestOversizedAndEndlessResultsAreCut(t *testing.T) {
	r := newRig(t, "", func(r *rig) { r.opts.MaxResult, r.opts.MaxStream = 32<<10, 256<<10 })
	// a plain answer over the limit
	r.tp.BigBytes = 100 << 10
	w, m := r.call("svc", "alice", "acme", "big", `{}`)
	res := result(t, w, m)
	if res["isError"] != true || !strings.Contains(text(res), "longer than the limit of 32768 bytes") || strings.Contains(w.Body.String(), "xxxxxxxx") {
		t.Fatalf("%s", w.Body)
	}
	// a stream with no end, and no answer in it: read up to the limit and not a byte further, then the call ends
	r.tp.StreamedBytes = 16 << 20
	w, m = r.call("svc", "alice", "acme", "endless", `{}`)
	res = result(t, w, m)
	if res["isError"] != true || !strings.Contains(text(res), "longer than the limit of 262144 bytes") {
		t.Fatalf("%s", w.Body)
	}
	// the double stops writing when the bridge closes the connection: Close in the cleanup would wait for it for ever otherwise
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		a := r.tp.StreamBytesSent()
		time.Sleep(100 * time.Millisecond)
		if r.tp.StreamBytesSent() == a {
			break
		}
	}
	// the double was ready to write 16 MiB; the bridge read 256 KiB and closed the connection, so what the double got
	// to write is what the sockets could hold, not the stream
	if sent := r.tp.StreamBytesSent(); sent >= 16<<20 {
		t.Fatalf("the double wrote all %d bytes of its stream: the bridge did not stop reading", sent)
	}
	if !strings.Contains(r.metricsText(), `outcome="result_too_large"} 2`) {
		t.Fatalf("%s", r.metricsText())
	}
}

func (r *rig) metricsText() string {
	w := httptest.NewRecorder()
	r.met.Write(w)
	return w.Body.String()
}

func TestRequestsTheThirdPartyMakesOfTheClientAreRefused(t *testing.T) {
	r := newRig(t, "", nil)
	for tool, want := range map[string]string{"sampling": "sampling/createMessage", "input": "input_required", "task": "task"} {
		w, m := r.call("svc", "alice", "acme", tool, `{}`)
		res := result(t, w, m)
		if res["isError"] != true || !strings.Contains(text(res), want) || !strings.Contains(text(res), "may not ask the client") && tool != "task" {
			t.Errorf("%s: %s", tool, w.Body)
		}
		if strings.Contains(w.Body.String(), "after the request") || strings.Contains(w.Body.String(), "t1") || strings.Contains(w.Body.String(), "inputRequests") {
			t.Errorf("%s: something of the third party's request or answer was relayed: %s", tool, w.Body)
		}
	}
	if !strings.Contains(r.metricsText(), `outcome="reverse_refused"} 3`) {
		t.Fatalf("%s", r.metricsText())
	}
}

func TestKeysOfThePlatformsNamespaceAreRemovedFromResultsAndToolMetadata(t *testing.T) {
	r := newRig(t, "", nil)
	w, m := r.call("svc", "alice", "acme", "telos", `{}`)
	res := result(t, w, m)
	if strings.Contains(w.Body.String(), "io.idp.telos/") || strings.Contains(w.Body.String(), "evil.example") {
		t.Fatalf("the third party's key got through: %s", w.Body)
	}
	if res["_meta"].(map[string]any)["vendor/ok"] != float64(1) || !strings.Contains(w.Body.String(), `"keep":"me"`) {
		t.Fatalf("what is not in the namespace was removed too: %s", w.Body)
	}
	if !strings.Contains(w.Body.String(), "12345678901234567890") {
		t.Fatalf("a large number was rounded: %s", w.Body)
	}
	// the listing
	w, m = mcptest.Post(r.h, Path("svc"), mcptest.ListBody(), nil)
	result(t, w, m)
	if strings.Contains(w.Body.String(), "io.idp.telos/") {
		t.Fatalf("the tool metadata: %s", w.Body)
	}
	var found bool
	for _, x := range m["result"].(map[string]any)["tools"].([]any) {
		tool := x.(map[string]any)
		if tool["name"] == "telos" {
			found = true
			if tool["_meta"].(map[string]any)["vendor/ok"] != float64(1) || tool["annotations"].(map[string]any)["readOnlyHint"] != true {
				t.Fatalf("%v", tool)
			}
		}
	}
	if !found {
		t.Fatal("the tool is gone")
	}
}

func TestTextThatTriesToInstructTheModelIsRelayedAsDataAndChangesNothing(t *testing.T) {
	r := newRig(t, "", nil)
	w, m := r.call("svc", "alice", "acme", "inject", `{}`)
	res := result(t, w, m)
	// the bridge neither obeys it nor edits it: it is the result of a tool, which the host marks as untrusted
	if text(res) != thirdparty.Injected || res["isError"] != nil || len(r.tp.Calls()) != 1 {
		t.Fatalf("%s", w.Body)
	}
}

func TestAMemberWithoutATokenGetsAuthorizationRequiredAndTheThirdPartyReceivesNothing(t *testing.T) {
	r := newRig(t, "", nil)
	r.tok.by[auth.Subject{Tenant: "acme", Member: "bob"}] = "tok-bob"
	r.tp.Tokens = map[string]string{"tok-bob": "bob"}
	// bob has connected the service; alice has not
	w, m := r.call("needs-auth", "alice", "acme", "whoami", `{}`)
	res := result(t, w, m)
	if res["isError"] != true || !strings.Contains(text(res), "connect Notes in the Workspace") {
		t.Fatalf("%s", w.Body)
	}
	// structuredContent is exactly the marker with the connection id: no address, no other key
	sc := asJSON(res["structuredContent"])
	if sc != `{"io.idp.telos/authorizationRequired":{"connection":"needs-auth"}}` {
		t.Fatalf("structuredContent: %s", sc)
	}
	if strings.Contains(w.Body.String(), "://") || strings.Contains(strings.ToLower(w.Body.String()), "http") {
		t.Fatalf("an address in the answer: %s", w.Body)
	}
	if n := len(r.tp.Requests()); n != 0 {
		t.Fatalf("the third party received %d requests for a member who has not authorized", n)
	}
	// the same subject in another tenant is another member; and bob's token is bob's alone
	if w, m = r.call("needs-auth", "bob", "other-tenant", "whoami", `{}`); result(t, w, m)["isError"] != true || len(r.tp.Requests()) != 0 {
		t.Fatalf("bob of another tenant: %s", w.Body)
	}
	w, m = r.call("needs-auth", "bob", "acme", "whoami", `{}`)
	if res = result(t, w, m); text(res) != "token of bob" || res["isError"] != nil {
		t.Fatalf("%s", w.Body)
	}
	if got := r.tp.Calls(); len(got) != 1 || got[0].Header.Get("Authorization") != "Bearer tok-bob" {
		t.Fatalf("%+v", got)
	}
	// who the source was asked about is who the gateway signed, in each call
	asked := r.tok.Asked()
	if len(asked) != 3 || asked[0] != (auth.Subject{Tenant: "acme", Member: "alice"}) || asked[1] != (auth.Subject{Tenant: "other-tenant", Member: "bob"}) || asked[2] != (auth.Subject{Tenant: "acme", Member: "bob"}) {
		t.Fatalf("%v", asked)
	}
	// a token is never in an answer, a log line or a metric
	for _, s := range []string{w.Body.String(), r.log.String(), r.metricsText()} {
		if strings.Contains(s, "tok-bob") {
			t.Fatalf("the token is in %q", s)
		}
	}
}

func TestAMemberArgumentCannotNameAnotherMember(t *testing.T) {
	r := newRig(t, "", nil)
	r.tok.by[auth.Subject{Tenant: "acme", Member: "bob"}] = "tok-bob"
	r.tp.Tokens = map[string]string{"tok-bob": "bob"}
	for _, args := range []string{`{"member":"bob","subject":"bob","tenant":"acme"}`} {
		w, m := r.call("needs-auth", "alice", "acme", "whoami", args)
		if res := result(t, w, m); res["isError"] != true {
			t.Fatalf("%s", w.Body)
		}
	}
	// nor can _meta: the unsigned caller of the gateway's older forwarding is ignored
	w, m := mcptest.Post(r.h, Path("needs-auth"), r.gw.CallBody(Audience(base, "needs-auth"), "alice", "acme", "whoami", `{}`, `"io.idp.telos/caller":{"subject":"bob","tenant":"acme"}`), nil)
	if res := result(t, w, m); res["isError"] != true || len(r.tp.Requests()) != 0 {
		t.Fatalf("%s", w.Body)
	}
}

func TestA401IsAnsweredByARefreshOnceAndATokenThatCannotBeRefreshedMeansAuthorizationRequired(t *testing.T) {
	r := newRig(t, "", nil)
	who := auth.Subject{Tenant: "acme", Member: "bob"}
	r.tok.by[who] = "stale"
	r.tp.Tokens = map[string]string{"fresh": "bob"}
	refreshed := 0
	r.tok.refresh = func(rejected string) (string, error) {
		refreshed++
		if rejected != "stale" {
			t.Errorf("the source was told %q was rejected", rejected)
		}
		return "fresh", nil
	}
	w, m := r.call("needs-auth", "bob", "acme", "whoami", `{}`)
	if res := result(t, w, m); text(res) != "token of bob" || refreshed != 1 {
		t.Fatalf("%s (refreshed %d times)", w.Body, refreshed)
	}
	// a refresh that gives the same useless token: one retry, then the member has to authorize again
	r.tok.refresh = func(string) (string, error) { refreshed++; return "stale", nil }
	refreshed = 0
	r.tok.by[who] = "stale"
	w, m = r.call("needs-auth", "bob", "acme", "whoami", `{}`)
	if res := result(t, w, m); res["isError"] != true || asJSON(res["structuredContent"]) != `{"io.idp.telos/authorizationRequired":{"connection":"needs-auth"}}` || refreshed != 1 {
		t.Fatalf("%s (refreshed %d times)", w.Body, refreshed)
	}
	// no refresh possible
	r.tok.refresh = nil
	w, m = r.call("needs-auth", "bob", "acme", "whoami", `{}`)
	if res := result(t, w, m); res["isError"] != true || !strings.Contains(asJSON(res["structuredContent"]), "authorizationRequired") {
		t.Fatalf("%s", w.Body)
	}
}

func TestAConnectionThatNeedsNoTokenAndIsAskedForOneSaysSo(t *testing.T) {
	r := newRig(t, "", nil)
	r.tp.Tokens = map[string]string{"x": "x"}
	w, m := r.call("svc", "alice", "acme", "echo", `{}`)
	res := result(t, w, m)
	if res["isError"] != true || strings.Contains(asJSON(res), "authorizationRequired") || !strings.Contains(text(res), "not set up") {
		t.Fatalf("%s", w.Body)
	}
}

// resolver answers names from a table.
type resolver map[string][]string

func (r resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, a := range r[host] {
		out = append(out, netip.MustParseAddr(a))
	}
	if out == nil {
		return nil, errors.New("no such host")
	}
	return out, nil
}

func TestAddressRulesRefuseANameThatResolvesToAPrivateAddressAndConnectToNothing(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	gw := mcptest.New()
	cs, err := config.Parse([]byte(`
connections:
  - {id: third, title: Third, endpoint: "https://third.example.com/mcp", authorization: {mode: none}}
  - {id: meta, title: Meta, endpoint: "https://meta.example.com/mcp", authorization: {mode: none}}
  - {id: good, title: Good, endpoint: "https://good.example.com/mcp", authorization: {mode: none}}
`), config.Options{})
	if err != nil {
		t.Fatal(err)
	}
	h, err := Handler(cs, Options{BaseURL: base, CallerKeysPEM: gw.PEM(), CallTimeout: 5 * time.Second,
		Egress: egress.Options{
			// one public and one private answer is what an attacker who owns the name sends
			Resolver: resolver{"third.example.com": {"93.184.216.34", "10.0.0.5"}, "meta.example.com": {"169.254.169.254"}, "good.example.com": {"93.184.216.34"}},
			Dial: func(_ context.Context, _, address string) (net.Conn, error) {
				mu.Lock()
				dialed = append(dialed, address)
				mu.Unlock()
				return nil, errors.New("no network in this test")
			}},
		Deps: bridge.Deps{Tokens: auth.NoTokens{}, Reviewer: auth.NoReviewer{}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"third", "meta"} {
		w, m := mcptest.Post(h, Path(id), gw.CallBody(Audience(base, id), "alice", "acme", "echo", `{}`, ""), nil)
		if res := result(t, w, m); res["isError"] != true || !strings.Contains(text(res), "did not answer") {
			t.Fatalf("%s: %s", id, w.Body)
		}
	}
	if len(dialed) != 0 {
		t.Fatalf("connected to %v", dialed)
	}
	// the check is not a blanket refusal: a name with only public answers is dialed, at the address that was checked
	mcptest.Post(h, Path("good"), gw.CallBody(Audience(base, "good"), "alice", "acme", "echo", `{}`, ""), nil)
	if len(dialed) != 1 || dialed[0] != "93.184.216.34:443" {
		t.Fatalf("dialed %v", dialed)
	}
}

func TestARedirectToAPrivateAddressIsNotFollowed(t *testing.T) {
	victim := thirdparty.New() // a server on a private (loopback) address that is not an exempt origin of the bridge
	defer victim.Close()
	r := newRig(t, "", nil)
	r.tp.RedirectTo = victim.URL()
	w, m := r.call("svc", "alice", "acme", "echo", `{}`)
	if res := result(t, w, m); res["isError"] != true || !strings.Contains(text(res), "could not be used") {
		t.Fatalf("%s", w.Body)
	}
	if n := len(victim.Requests()); n != 0 {
		t.Fatalf("the redirect target received %d requests", n)
	}
	// nor does a redirect carry the member's token: the 307 of a connection with a token goes nowhere either
	r.tok.by[auth.Subject{Tenant: "acme", Member: "bob"}] = "tok-bob"
	r.call("needs-auth", "bob", "acme", "whoami", `{}`)
	if n := len(victim.Requests()); n != 0 {
		t.Fatalf("the redirect target received %d requests", n)
	}
}

func TestTheRateLimitsArePerMemberAndPerConnectionAndSlide(t *testing.T) {
	r := newRig(t, "    rateLimit: {windowSeconds: 60, connectionCalls: 5, memberCalls: 2}", nil)
	call := func(member string) map[string]any {
		w, m := r.call("svc", member, "acme", "echo", `{"text":"x"}`)
		return result(t, w, m)
	}
	if call("alice")["isError"] != nil || call("alice")["isError"] != nil {
		t.Fatal("the first two calls are within the limit")
	}
	res := call("alice")
	if res["isError"] != true || !strings.Contains(text(res), "You are calling Test Service too often") || !strings.Contains(text(res), "60 seconds") {
		t.Fatalf("%v", res)
	}
	if n := len(r.tp.Calls()); n != 2 {
		t.Fatalf("the refused call went out: %d calls", n)
	}
	// another member is not affected, and the refusals did not use up the allowance
	if call("bob")["isError"] != nil {
		t.Fatal("bob is limited by alice's calls")
	}
	call("alice")
	call("alice")
	r.clock.Advance(61 * time.Second)
	if call("alice")["isError"] != nil {
		t.Fatal("the window does not slide")
	}
	// the connection's own limit: 5 calls of all members together in the window
	r.clock.Advance(61 * time.Second)
	for _, m := range []string{"m1", "m2", "m3", "m4", "m5"} {
		if call(m)["isError"] != nil {
			t.Fatalf("%s", m)
		}
	}
	res = call("m6")
	if res["isError"] != true || !strings.Contains(text(res), "Everyone together is calling Test Service too often") {
		t.Fatalf("%v", res)
	}
}

func TestTheCircuitBreakerOpensAfterConsecutiveFailuresAndClosesAfterATrial(t *testing.T) {
	r := newRig(t, "    breaker: {failures: 3, openSeconds: 30}", nil)
	call := func() map[string]any {
		w, m := r.call("svc", "alice", "acme", "echo", `{"text":"x"}`)
		return result(t, w, m)
	}
	r.tp.Status = 503
	for i := 0; i < 3; i++ {
		if res := call(); res["isError"] != true || !strings.Contains(text(res), "HTTP 503") {
			t.Fatalf("%d: %v", i, res)
		}
	}
	// open: the fourth call is not made
	if res := call(); !strings.Contains(text(res), "is not answering at the moment") || !strings.Contains(text(res), "30 seconds") || len(r.tp.Requests()) != 3 {
		t.Fatalf("%v (%d requests)", res, len(r.tp.Requests()))
	}
	// the listing is behind the same breaker
	if w, _ := mcptest.Post(r.h, Path("svc"), mcptest.ListBody(), nil); w.Code != http.StatusServiceUnavailable || len(r.tp.Requests()) != 3 {
		t.Fatalf("listing while open: %d", w.Code)
	}
	// after the pause one trial goes out; it fails, so it is open again for another pause
	r.clock.Advance(31 * time.Second)
	call()
	if len(r.tp.Requests()) != 4 {
		t.Fatalf("the trial: %d requests", len(r.tp.Requests()))
	}
	if res := call(); !strings.Contains(text(res), "is not answering") || len(r.tp.Requests()) != 4 {
		t.Fatalf("%v", res)
	}
	// the third party recovers: the next trial closes the breaker
	r.tp.Status = 0
	r.clock.Advance(31 * time.Second)
	if res := call(); res["isError"] != nil {
		t.Fatalf("%v", res)
	}
	if res := call(); res["isError"] != nil || r.met == nil {
		t.Fatalf("%v", res)
	}
	if !strings.Contains(r.metricsText(), `idp_bridge_breaker_state{connection="svc"} 0`) {
		t.Fatalf("%s", r.metricsText())
	}
	// a third party that answers "no" is well: 4xx and tool errors do not count
	r.tp.Status = 403
	for i := 0; i < 5; i++ {
		call()
	}
	if len(r.tp.Requests()) != 11 {
		t.Fatalf("%d requests: refusals by the third party opened the breaker", len(r.tp.Requests()))
	}
}

func TestAuditLinesAndMetricsHoldNoArgumentsResultsOrTokens(t *testing.T) {
	r := newRig(t, "", nil)
	who := auth.Subject{Tenant: "acme", Member: "member-uuid-1234"}
	r.tok.by[who] = "SECRET-TOKEN"
	r.tp.Tokens = map[string]string{"SECRET-TOKEN": "SECRET-RESULT"}
	w, m := r.call("needs-auth", who.Member, who.Tenant, "whoami", `{"text":"SECRET-ARGUMENT"}`)
	if text(result(t, w, m)) != "token of SECRET-RESULT" {
		t.Fatalf("%s", w.Body)
	}
	logs := r.log.String()
	for _, secret := range []string{"SECRET-TOKEN", "SECRET-ARGUMENT", "SECRET-RESULT", who.Member} {
		if strings.Contains(logs, secret) || strings.Contains(r.metricsText(), secret) {
			t.Errorf("%q is in the log or the metrics:\n%s", secret, logs)
		}
	}
	var line map[string]any
	for _, l := range strings.Split(strings.TrimSpace(logs), "\n") {
		var x map[string]any
		if json.Unmarshal([]byte(l), &x) == nil && x["msg"] == "audit" {
			line = x
		}
	}
	if line["tool"] != "whoami" || line["connection"] != "needs-auth" || line["tenant"] != "acme" || line["outcome"] != "ok" || line["bytes"] == nil || line["ms"] == nil {
		t.Fatalf("%v", line)
	}
	if h, _ := line["member"].(string); len(h) != 8 {
		t.Fatalf("the member is %q, want a hash prefix", h)
	}
	if !strings.Contains(r.metricsText(), `idp_bridge_calls_total{connection="needs-auth",outcome="ok"} 1`) {
		t.Fatalf("%s", r.metricsText())
	}
}

func TestEachConnectionIsItsOwnEndpointAndUnknownPathsAreNotFound(t *testing.T) {
	r := newRig(t, "", nil)
	for _, p := range []string{"/mcp", "/mcp/", "/mcp/other", "/", "/mcp/svc/extra"} {
		if w, _ := mcptest.Post(r.h, p, mcptest.ListBody(), nil); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if len(r.tp.Requests()) != 0 {
		t.Fatal("a request went out")
	}
}

func TestAThirdPartyThatDoesNotSpeakTheProtocolIsAnUnusableAnswer(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>login</html>"))
	}))
	defer bad.Close()
	gw := mcptest.New()
	cs, err := config.Parse([]byte(`{connections: [{id: html, title: Html, endpoint: "`+bad.URL+`/mcp", authorization: {mode: none}}]}`),
		config.Options{TestOrigins: map[string]bool{strings.TrimPrefix(bad.URL, "http://"): true}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := Handler(cs, Options{BaseURL: base, CallerKeysPEM: gw.PEM(), Egress: egress.Options{TestOrigins: map[string]bool{strings.TrimPrefix(bad.URL, "http://"): true}},
		Deps: bridge.Deps{Tokens: auth.NoTokens{}, Reviewer: auth.NoReviewer{}}})
	if err != nil {
		t.Fatal(err)
	}
	w, m := mcptest.Post(h, Path("html"), gw.CallBody(Audience(base, "html"), "alice", "acme", "echo", `{}`, ""), nil)
	if res := result(t, w, m); res["isError"] != true || strings.Contains(w.Body.String(), "login") {
		t.Fatalf("%s", w.Body)
	}
	if w, _ := mcptest.Post(h, Path("html"), mcptest.ListBody(), nil); w.Code != http.StatusBadGateway {
		t.Fatalf("listing: %d", w.Code)
	}
}

func TestTheListingCountsForTheConnectionsLimitAndForNoMember(t *testing.T) {
	r := newRig(t, "    rateLimit: {windowSeconds: 60, connectionCalls: 3, memberCalls: 1}", nil)
	for i := 0; i < 3; i++ {
		if w, _ := mcptest.Post(r.h, Path("svc"), mcptest.ListBody(), nil); w.Code != 200 {
			t.Fatalf("listing %d: %d", i, w.Code)
		}
	}
	w, _ := mcptest.Post(r.h, Path("svc"), mcptest.ListBody(), nil)
	if w.Code != http.StatusTooManyRequests || len(r.tp.Requests()) != 3 {
		t.Fatalf("%d, %d requests", w.Code, len(r.tp.Requests()))
	}
	r.clock.Advance(61 * time.Second)
	if w, _ := mcptest.Post(r.h, Path("svc"), mcptest.ListBody(), nil); w.Code != 200 {
		t.Fatalf("after the window: %d", w.Code)
	}
}

func TestAToolNameThatCannotBeSentIsAToolErrorAndNothingIsSent(t *testing.T) {
	r := newRig(t, "", nil)
	w, m := r.call("svc", "alice", "acme", "a\nb", `{}`)
	if res := result(t, w, m); res["isError"] != true || len(r.tp.Requests()) != 0 {
		t.Fatalf("%s", w.Body)
	}
}
