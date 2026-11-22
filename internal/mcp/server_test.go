package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newServer(t *testing.T, be Backend) *Server {
	t.Helper()
	return New("github", "1", "", be, vectorVerifier(t))
}

func TestDiscoverIsStrictlyModernAndOffersToolsWithoutAskingTheBackend(t *testing.T) {
	be := &fakeBackend{}
	w, m := post(t, newServer(t, be), ok, `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+meta+`}}`)
	res, _ := m["result"].(map[string]any)
	if w.Code != 200 || res["resultType"] != "complete" || len(res["supportedVersions"].([]any)) != 1 || res["supportedVersions"].([]any)[0] != "2026-07-28" {
		t.Fatalf("%d %v", w.Code, m)
	}
	if _, ok := res["capabilities"].(map[string]any)["tools"]; !ok {
		t.Fatal("no tools capability")
	}
	if info := res["_meta"].(map[string]any)["io.modelcontextprotocol/serverInfo"].(map[string]any); info["name"] != "github" {
		t.Fatalf("%v", info)
	}
	if be.lists != 0 || len(be.calls) != 0 {
		t.Fatal("discovery went to the backend")
	}
}

func TestAdmissionRules(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		body    string
		status  int
		code    float64
	}{
		{"no version header", nil, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}`, 400, CodeUnsupported},
		{"old version", map[string]string{"MCP-Protocol-Version": "2025-06-18"}, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}`, 400, CodeUnsupported},
		{"legacy initialize", ok, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{` + meta + `}}`, 404, CodeNotFound},
		{"batch", ok, `[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`, 400, CodeInvalidRequest},
		{"garbage", ok, `{`, 400, CodeParse},
		{"method header mismatch", map[string]string{"MCP-Protocol-Version": ProtocolVersion, "Mcp-Method": "tools/call"}, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}`, 400, CodeMismatch},
		{"no method header", map[string]string{"MCP-Protocol-Version": ProtocolVersion, "Mcp-Method": ""}, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}`, 400, CodeMismatch},
		{"no method header on a notification", map[string]string{"MCP-Protocol-Version": ProtocolVersion, "Mcp-Method": ""}, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}`, 400, CodeMismatch},
		{"no version header and no method header", map[string]string{"Mcp-Method": ""}, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}`, 400, CodeUnsupported},
		{"no _meta", ok, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, 400, CodeInvalidParams},
		{"body version differs", ok, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18","io.modelcontextprotocol/clientCapabilities":{}}}}`, 400, CodeMismatch},
		{"no capabilities", ok, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`, 400, CodeInvalidParams},
		{"ping is removed", ok, `{"jsonrpc":"2.0","id":1,"method":"ping","params":{` + meta + `}}`, 404, CodeNotFound},
		{"fractional id", ok, `{"jsonrpc":"2.0","id":1.5,"method":"tools/list","params":{` + meta + `}}`, 400, CodeInvalidRequest},
		{"name header mismatch", map[string]string{"MCP-Protocol-Version": ProtocolVersion, "Mcp-Name": "other"}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo",` + meta + `}}`, 400, CodeMismatch},
	}
	for _, c := range cases {
		be := &fakeBackend{}
		w, m := post(t, newServer(t, be), c.headers, c.body)
		e, _ := m["error"].(map[string]any)
		if w.Code != c.status || e == nil || e["code"] != c.code {
			t.Errorf("%s: %d %v", c.name, w.Code, m)
		}
		if be.lists != 0 || len(be.calls) != 0 {
			t.Errorf("%s: the request reached the backend", c.name)
		}
	}
}

func TestTheMethodHeaderIsRequiredAndMustMatchTheBody(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}`
	h := func(method string) map[string]string {
		return map[string]string{"MCP-Protocol-Version": ProtocolVersion, "Mcp-Method": method}
	}
	s := newServer(t, &fakeBackend{})
	w, m := post(t, s, h(""), body)
	e, _ := m["error"].(map[string]any)
	if w.Code != 400 || e == nil || e["code"] != float64(CodeMismatch) || !strings.Contains(e["message"].(string), "required") {
		t.Fatalf("without the header: %d %v", w.Code, m)
	}
	w, m = post(t, s, h("tools/call"), body)
	e, _ = m["error"].(map[string]any)
	if w.Code != 400 || e == nil || e["code"] != float64(CodeMismatch) || !strings.Contains(e["message"].(string), "does not match") {
		t.Fatalf("with another method: %d %v", w.Code, m)
	}
	if w, m = post(t, s, h("tools/list"), body); w.Code != 200 || m["result"] == nil {
		t.Fatalf("with the matching header: %d %v", w.Code, m)
	}
	note := `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}`
	if w, _ = post(t, s, h(""), note); w.Code != 400 {
		t.Fatalf("a notification without the header: %d", w.Code)
	}
	if w, _ = post(t, s, h("notifications/cancelled"), note); w.Code != 202 {
		t.Fatalf("a notification with the header: %d", w.Code)
	}
}

func TestOnlyPostIsAccepted(t *testing.T) {
	w := httptest.NewRecorder()
	newServer(t, &fakeBackend{}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/mcp/x", nil))
	if w.Code != 405 {
		t.Fatalf("%d", w.Code)
	}
}

// A tools/call without an assertion is refused with 403 before the backend is touched, let alone a token looked up.
func TestACallWithoutAnAssertionIsRefusedAndTheBackendNeverSeesIt(t *testing.T) {
	be := &fakeBackend{}
	s := newServer(t, be)
	w, m := post(t, s, ok, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"web_search","arguments":{},`+meta+`}}`)
	if w.Code != http.StatusForbidden || len(be.calls) != 0 || m["error"] == nil {
		t.Fatalf("%d, the backend saw %d calls: %v", w.Code, len(be.calls), m)
	}
}

func TestTheBackendsErrorsAreAnsweredAndAnUnexpectedOneLeaksNothing(t *testing.T) {
	be := &fakeBackend{err: &Error{Code: CodeInternal, Message: "upstream is down", Status: 502}}
	w, m := post(t, newServer(t, be), ok, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{`+meta+`}}`)
	if w.Code != 502 || m["error"].(map[string]any)["message"] != "upstream is down" {
		t.Fatalf("%d %v", w.Code, m)
	}
	be.err = http.ErrHandlerTimeout
	w, m = post(t, newServer(t, be), ok, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{`+meta+`}}`)
	if w.Code != 500 || strings.Contains(w.Body.String(), "timeout") || m["error"] == nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestTheProgressTokenIsPassedOnOnlyIfItIsValid(t *testing.T) {
	for token, want := range map[string]bool{`"abc"`: true, `7`: true, `1.5`: false, `{"a":1}`: false, `"` + strings.Repeat("x", 129) + `"`: false, `"a\nb"`: false, `true`: false} {
		if got := ValidProgressToken([]byte(token)); got != want {
			t.Errorf("%.20s: %v", token, got)
		}
	}
}
