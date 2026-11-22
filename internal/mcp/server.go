// Package mcp serves one connection of the bridge as an MCP 2026-07-28 modern server over Streamable HTTP (JSON
// responses): server/discover, tools/list and tools/call. The admission rules are those of idp-mcp's gateway, copied
// as idp-web copied them (idp-web ADR-0001 D1; this repository's ADR-0001 D1): the gateway is the only client this
// server is meant to have.
//
// It differs from idp-web's copy in one place: the tools are not a fixed list the server owns. tools/list and
// tools/call are handed to a Backend, which forwards them to the third party and answers with what came back, so
// the server never needs to know a tool by name and a tool the third party adds later is callable without a release
// of the bridge (the gateway's pinned catalog and drift check are what keep the set under review, idp-mcp ADR-0001 D51).
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
)

// ProtocolVersion is the only revision spoken, to the gateway and to the third party.
const ProtocolVersion = "2026-07-28"

const (
	MetaVersion = "io.modelcontextprotocol/protocolVersion"
	MetaCaps    = "io.modelcontextprotocol/clientCapabilities"
	MetaServer  = "io.modelcontextprotocol/serverInfo"
	// MetaProgress is the key of the progress token in a request's _meta.
	MetaProgress = "progressToken"
	maxBody      = 1 << 20
)

// JSON-RPC and MCP error codes.
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeNotFound       = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
	CodeMismatch       = -32020
	CodeUnsupported    = -32022
)

// Error is a JSON-RPC error. A Backend returns one to have the call answered with it.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
	// Status is the HTTP status of the answer (200 if zero).
	Status int `json:"-"`
}

func (e *Error) Error() string { return e.Message }

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Caller is the verified caller the gateway forwarded: what the gateway signed, nothing else.
type Caller struct {
	Subject string   `json:"subject"`
	Tenant  string   `json:"tenant"`
	Roles   []string `json:"roles"`
	Client  string   `json:"client,omitempty"`
	Actor   string   `json:"actor,omitempty"`
}

// Owner is the stable identity of a member: tenant and subject.
func (c Caller) Owner() string {
	if c.Subject == "" {
		return ""
	}
	return c.Tenant + "/" + c.Subject
}

// Call is one tools/call as the Backend sees it. Params is the request's params as the client sent them, _meta
// included: the Backend builds what it forwards from Name, Arguments and the progress token, never from Params
// itself, so nothing a client invented can travel on (ADR-0001 D9).
type Call struct {
	Name      string
	Arguments json.RawMessage // the arguments object as sent, "{}" if none
	Progress  json.RawMessage // the progress token if the client sent one, else nil
	Caller    Caller
}

// Backend answers the two methods that go to the third party. Both return the result object (what goes in the
// JSON-RPC "result", resultType included) or an *Error; any other error is answered as an internal error without its text.
type Backend interface {
	ListTools(ctx context.Context) (json.RawMessage, error)
	CallTool(ctx context.Context, c Call) (json.RawMessage, error)
}

// Server is the MCP endpoint of one connection.
type Server struct {
	Name, Version string
	Instructions  string
	Backend       Backend
	// Callers makes every tools/call prove its caller with the gateway's assertion (ADR-0001 D2). It is not optional:
	// the caller decides whose token is used, and a caller nobody signed for would be a way to use another member's.
	Callers *CallerVerifier
	Log     *slog.Logger
}

// New builds the server; callers must not be nil.
func New(name, version, instructions string, b Backend, callers *CallerVerifier) *Server {
	if callers == nil {
		panic("mcp.New: a server without a caller verifier would take any caller's word for who they are")
	}
	return &Server{Name: name, Version: version, Instructions: instructions, Backend: b, Callers: callers}
}

func write(w http.ResponseWriter, status int, id json.RawMessage, result any, e *Error) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	msg := map[string]any{"jsonrpc": "2.0", "id": id}
	if e != nil {
		msg["error"] = e
	} else {
		msg["result"] = result
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(msg)
}

func validID(raw json.RawMessage) json.RawMessage {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil
	}
	switch x := v.(type) {
	case string:
		return raw
	case json.Number:
		if _, err := x.Int64(); err == nil {
			return raw
		}
	}
	return nil
}

// ServeHTTP handles POST on the connection's path.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		write(w, http.StatusMethodNotAllowed, nil, nil, &Error{Code: CodeInvalidRequest, Message: "Use POST"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		write(w, http.StatusRequestEntityTooLarge, nil, nil, &Error{Code: CodeInvalidRequest, Message: "Request body too large"})
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		write(w, 400, nil, nil, &Error{Code: CodeInvalidRequest, Message: "JSON-RPC batches are not supported"})
		return
	}
	var req request
	if json.Unmarshal(trimmed, &req) != nil {
		write(w, 400, nil, nil, &Error{Code: CodeParse, Message: "Parse error"})
		return
	}
	id := validID(req.ID)
	if req.JSONRPC != "2.0" || req.Method == "" || (len(req.ID) > 0 && string(bytes.TrimSpace(req.ID)) != "null" && id == nil) {
		write(w, 400, id, nil, &Error{Code: CodeInvalidRequest, Message: "Invalid JSON-RPC request"})
		return
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != ProtocolVersion {
		write(w, 400, id, nil, &Error{Code: CodeUnsupported, Message: "Unsupported protocol version",
			Data: map[string]any{"supported": []string{ProtocolVersion}}})
		return
	}
	// The header is required on every request, notifications included (2026-07-28 transport; idp-mcp ADR-0001 D12 made
	// the gateway require it). It comes after the protocol-version check, as in the gateway, so a client of another
	// revision is told the revision is unsupported, not that a header of this one is missing; and before the
	// notification return, so those are not exempt.
	m := r.Header.Get("Mcp-Method")
	if m == "" {
		write(w, 400, id, nil, &Error{Code: CodeMismatch, Message: "Mcp-Method header is required"})
		return
	}
	if m != req.Method {
		write(w, 400, id, nil, &Error{Code: CodeMismatch, Message: "Mcp-Method header does not match the body method"})
		return
	}
	if len(id) == 0 { // a notification: accepted, no body
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(req.Params, &params) != nil || params == nil {
		write(w, 400, id, nil, &Error{Code: CodeInvalidParams, Message: "params must be an object"})
		return
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(params["_meta"], &meta) != nil || meta == nil {
		write(w, 400, id, nil, &Error{Code: CodeInvalidParams, Message: "params._meta must be an object"})
		return
	}
	var ver string
	if json.Unmarshal(meta[MetaVersion], &ver) != nil || ver != ProtocolVersion {
		write(w, 400, id, nil, &Error{Code: CodeMismatch, Message: "MCP header/body protocol version mismatch"})
		return
	}
	var caps map[string]json.RawMessage
	if json.Unmarshal(meta[MetaCaps], &caps) != nil || caps == nil {
		write(w, 400, id, nil, &Error{Code: CodeInvalidParams, Message: "params._meta is missing " + MetaCaps})
		return
	}
	switch req.Method {
	case "server/discover":
		// Answered here and not by the third party: the gateway registers and probes this endpoint, and what it asks
		// is whether this server speaks 2026-07-28 and offers tools, which is a fact about the bridge. A third party
		// that does not speak it shows at tools/list.
		res := map[string]any{"supportedVersions": []string{ProtocolVersion}, "resultType": "complete",
			"capabilities": map[string]any{"tools": map[string]any{}},
			"_meta":        map[string]any{MetaServer: map[string]any{"name": s.Name, "version": s.Version}}}
		if s.Instructions != "" {
			res["instructions"] = s.Instructions
		}
		write(w, 200, id, res, nil)
	case "tools/list":
		// No caller: the gateway's registry and drift checks list tools without a member (a token for that is the
		// reviewer account's, ADR-0001 D13).
		s.answer(w, id, func() (json.RawMessage, error) { return s.Backend.ListTools(r.Context()) })
	case "tools/call":
		s.call(w, r, id, params, meta)
	default:
		write(w, 404, id, nil, &Error{Code: CodeNotFound, Message: "Method not found: " + req.Method})
	}
}

func (s *Server) answer(w http.ResponseWriter, id json.RawMessage, f func() (json.RawMessage, error)) {
	res, err := f()
	if err != nil {
		e, ok := err.(*Error)
		if !ok {
			// The text of an unexpected error is for the log; it may name an address or a header.
			if s.Log != nil {
				s.Log.Error("backend failed", "err", err.Error())
			}
			e = &Error{Code: CodeInternal, Message: "Internal error", Status: http.StatusInternalServerError}
		}
		status := e.Status
		if status == 0 {
			status = http.StatusOK
		}
		write(w, status, id, nil, e)
		return
	}
	write(w, 200, id, res, nil)
}

func (s *Server) call(w http.ResponseWriter, r *http.Request, id json.RawMessage, params, meta map[string]json.RawMessage) {
	var name string
	if json.Unmarshal(params["name"], &name) != nil || name == "" {
		write(w, 400, id, nil, &Error{Code: CodeInvalidParams, Message: "params.name must be a non-empty string"})
		return
	}
	if h := r.Header.Get("Mcp-Name"); h != "" && h != name {
		write(w, 400, id, nil, &Error{Code: CodeMismatch, Message: "invalid MCP routing header: Mcp-Name"})
		return
	}
	// The assertion is checked before anything else about the call is looked at, and before the Backend exists for
	// this request: a call nobody signed for never gets as far as a token lookup or a connection (ADR-0001 D2).
	var assertion string
	_ = json.Unmarshal(meta[MetaCallerAssertion], &assertion)
	c, err := s.Callers.Verify(assertion, "tools/call", params)
	if err != nil {
		if s.Log != nil {
			s.Log.Warn("caller assertion refused", "tool", name, "reason", err.Error(), "remote", r.RemoteAddr)
		}
		write(w, http.StatusForbidden, id, nil, &Error{Code: CodeInvalidRequest, Message: ErrAssertion.Error()})
		return
	}
	args := json.RawMessage("{}")
	if raw, ok := params["arguments"]; ok && string(bytes.TrimSpace(raw)) != "null" {
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil || obj == nil {
			write(w, 200, id, nil, &Error{Code: CodeInvalidParams, Message: "arguments must be an object"})
			return
		}
		args = raw
	}
	call := Call{Name: name, Arguments: args, Caller: c}
	if t, ok := meta[MetaProgress]; ok && ValidProgressToken(t) {
		call.Progress = t
	}
	s.answer(w, id, func() (json.RawMessage, error) { return s.Backend.CallTool(r.Context(), call) })
}
