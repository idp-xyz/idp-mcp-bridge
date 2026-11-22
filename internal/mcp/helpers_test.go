package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeBackend records what the server hands it and answers with a fixed list and a fixed result.
type fakeBackend struct {
	calls []Call
	lists int
	err   error
}

func (b *fakeBackend) ListTools(context.Context) (json.RawMessage, error) {
	b.lists++
	if b.err != nil {
		return nil, b.err
	}
	return json.RawMessage(`{"resultType":"complete","tools":[{"name":"echo","inputSchema":{"type":"object"}}]}`), nil
}

func (b *fakeBackend) CallTool(_ context.Context, c Call) (json.RawMessage, error) {
	b.calls = append(b.calls, c)
	if b.err != nil {
		return nil, b.err
	}
	return json.RawMessage(`{"resultType":"complete","content":[{"type":"text","text":"ran"}]}`), nil
}

func post(t *testing.T, s *Server, headers map[string]string, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/mcp/x", strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	// Mcp-Method is required: unless a test names it (an empty value sends none), it is the body's own method, as every
	// real client sends it.
	if _, named := headers["Mcp-Method"]; !named {
		var b struct{ Method string }
		_ = json.Unmarshal([]byte(body), &b)
		if b.Method != "" {
			r.Header.Set("Mcp-Method", b.Method)
		}
	}
	if r.Header.Get("Mcp-Method") == "" {
		r.Header.Del("Mcp-Method")
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w, m
}

var ok = map[string]string{"MCP-Protocol-Version": ProtocolVersion, "Content-Type": "application/json"}

const meta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`
