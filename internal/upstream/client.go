// Package upstream is the bridge's MCP 2026-07-28 client toward a third party (ADR-0001 D8 to D10). It forwards
// tools/list and tools/call and nothing else, and it is the one place where what the bridge sends and what it accepts
// are decided.
//
// What it sends is built from an allow-list, not cleaned of what is unwanted, so that a field nobody thought of is
// not sent either: the arguments the model made and the name of the tool, the protocol envelope (the version and
// empty client capabilities, as idp-mcp's gateway sends to an external target, ADR-0001 D51 b) and the progress token
// the caller sent; the request headers are Content-Type, Accept, MCP-Protocol-Version, Mcp-Method, Mcp-Name, the
// member's own token for the third party if there is one, a fixed User-Agent, and the Mcp-Param-* headers the tool's definition
// asks for, computed from the arguments (paramheaders.go). Nothing of the caller (no assertion, no tenant or member, no
// clientInfo), no trace headers, and no header copied from the gateway's request.
//
// What it accepts is bounded and judged: a plain answer up to MaxResult bytes, a stream up to MaxStream bytes in all
// and MaxResult for one event; a request the third party makes of the client (sampling, elicitation, roots, input
// required, a task) ends the call; the keys of the bridge's own namespace in the answer are removed (sanitize.go).
package upstream

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"idp-mcp-bridge/internal/mcp"
)

// Defaults of the bounds: the gateway's own for an external target (idp-mcp ADR-0001 D51 d), because the answer the
// bridge sends on is read by the gateway under them.
const (
	DefaultMaxResult = 1 << 20
	DefaultMaxStream = 4 << 20
	maxChallenge     = 1024
	maxRPCMessage    = 512
	maxPages         = 20
	maxTools         = 500
	maxToolName      = 256
	userAgent        = "idp-mcp-bridge"
)

// requestID is the id of every request: one request per connection, so it needs no uniqueness.
const requestID = "1"

var (
	// ErrUnauthorized: the third party answered 401.
	ErrUnauthorized = errors.New("the third party did not accept the credential")
	// ErrUnreachable: no answer; the connection failed, the address was refused, or the answer did not begin in time.
	ErrUnreachable = errors.New("the third party could not be reached")
	// ErrRedirect: the third party answered with a redirect, which is not followed.
	ErrRedirect = errors.New("the third party answered with a redirect")
	// ErrBadResponse: an answer that is not a 2026-07-28 answer to this request.
	ErrBadResponse = errors.New("the third party's answer is not usable")
	// ErrTooLarge: an answer or an event longer than the limits.
	ErrTooLarge = errors.New("the third party's answer is longer than the limit")
	// ErrReverse: the third party asked the client for something.
	ErrReverse = errors.New("the third party made a request of the client")
	// ErrBadName: a tool name that cannot be sent.
	ErrBadName = errors.New("the tool name cannot be sent")
)

// StatusError is an HTTP status the bridge did not expect, with the third party's challenge (WWW-Authenticate), which
// B2 reads for insufficient_scope.
type StatusError struct {
	Status    int
	Challenge string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("the third party answered HTTP %d", e.Status)
}

// Is makes a 401 match ErrUnauthorized.
func (e *StatusError) Is(target error) bool {
	return target == ErrUnauthorized && e.Status == http.StatusUnauthorized
}

// LimitError says which limit an answer exceeded.
type LimitError struct {
	Limit  int64
	Stream bool
}

func (e *LimitError) Error() string {
	if e.Stream {
		return fmt.Sprintf("the third party's stream is longer than %d bytes", e.Limit)
	}
	return fmt.Sprintf("the third party's answer is longer than %d bytes", e.Limit)
}
func (e *LimitError) Is(target error) bool { return target == ErrTooLarge }

// ReverseError says in the bridge's own words what the third party asked for; the method name is one of a fixed few.
type ReverseError struct{ Reason string }

func (e *ReverseError) Error() string        { return e.Reason }
func (e *ReverseError) Is(target error) bool { return target == ErrReverse }

// RPCError is a JSON-RPC error the third party answered, with a message cut to 512 bytes and without its data.
type RPCError struct {
	Code    int
	Message string
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("the third party answered with error %d", e.Code)
}

// Counts says whether an error is a sign that the third party is unwell, for the circuit breaker: it did not answer, or
// answered with a server error or with something that is not an answer. A refusal of the credential, of the request or
// of the call by the third party is an answer.
func Counts(err error) bool {
	var se *StatusError
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrUnreachable), errors.Is(err, ErrBadResponse), errors.Is(err, ErrRedirect):
		return true
	case errors.As(err, &se):
		return se.Status >= 500
	}
	return false
}

// Client is the client for one connection.
type Client struct {
	HTTP      *http.Client // from egress.NewClient
	Endpoint  string
	MaxResult int64
	MaxStream int64
}

// Reply is a result of the third party after the bridge has judged and cleaned it.
type Reply struct {
	// Result is the result object, with the bridge's keys removed and a resultType.
	Result json.RawMessage
	// IsError is the tool result's own isError.
	IsError bool
	// Bytes is how much of the third party's answer was read.
	Bytes int64
}

func (c *Client) limits() (int64, int64) {
	r, s := c.MaxResult, c.MaxStream
	if r <= 0 {
		r = DefaultMaxResult
	}
	if s <= 0 {
		s = DefaultMaxStream
	}
	return r, s
}

// envelope is the _meta the bridge sends: the version, empty client capabilities, and the progress token if there is
// one. It is made here, from nothing, and no field of the caller's request is copied into it.
func envelope(progress json.RawMessage) map[string]json.RawMessage {
	m := map[string]json.RawMessage{
		mcp.MetaVersion: json.RawMessage(`"` + mcp.ProtocolVersion + `"`),
		mcp.MetaCaps:    json.RawMessage(`{}`),
	}
	if len(progress) > 0 && mcp.ValidProgressToken(progress) {
		m[mcp.MetaProgress] = progress
	}
	return m
}

// ValidName says whether a tool name can be sent: not empty, at most 256 bytes, no control characters (it travels in
// the body and in the Mcp-Name header).
func ValidName(name string) bool {
	return name != "" && len(name) <= maxToolName && !strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// CallTool sends tools/call with the arguments and the progress token. token is the member's credential for this
// third party, or "" for a connection that needs none.
func (c *Client) CallTool(ctx context.Context, token, name string, args, progress json.RawMessage) (Reply, error) {
	return c.CallToolWithHeaders(ctx, token, name, args, progress, nil)
}

// CallToolWithHeaders is CallTool with the Mcp-Param-* headers the tool's definition asks for (ParamHeaders). Only headers of that
// family are sent: anything else in extra is dropped, so that it cannot become a way to send something the allow-list does not.
func (c *Client) CallToolWithHeaders(ctx context.Context, token, name string, args, progress json.RawMessage, extra http.Header) (Reply, error) {
	if !ValidName(name) {
		return Reply{}, ErrBadName
	}
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	n, _ := json.Marshal(name)
	params := map[string]json.RawMessage{"name": n, "arguments": args, "_meta": mustJSON(envelope(progress))}
	res, read, err := c.do(ctx, token, "tools/call", name, params, extra)
	if err != nil {
		return Reply{Bytes: read}, err
	}
	clean, isErr, err := Sanitize(res)
	if err != nil {
		return Reply{Bytes: read}, fmt.Errorf("%w: %v", ErrBadResponse, err)
	}
	return Reply{Result: clean, IsError: isErr, Bytes: read}, nil
}

// ListTools pages through tools/list and returns one result with all the tools, cleaned. token is the reviewer
// account's, or "".
func (c *Client) ListTools(ctx context.Context, token string) (Reply, error) {
	var tools []json.RawMessage
	var total int64
	cursor := ""
	for page := 0; page < maxPages; page++ {
		params := map[string]json.RawMessage{"_meta": mustJSON(envelope(nil))}
		if cursor != "" {
			params["cursor"], _ = json.Marshal(cursor)
		}
		res, read, err := c.do(ctx, token, "tools/list", "", params, nil)
		total += read
		if err != nil {
			return Reply{Bytes: total}, err
		}
		clean, _, err := Sanitize(res)
		if err != nil {
			return Reply{Bytes: total}, fmt.Errorf("%w: %v", ErrBadResponse, err)
		}
		var p struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
		}
		if json.Unmarshal(clean, &p) != nil || p.Tools == nil {
			return Reply{Bytes: total}, fmt.Errorf("%w: no tools array", ErrBadResponse)
		}
		tools = append(tools, p.Tools...)
		if len(tools) > maxTools {
			return Reply{Bytes: total}, fmt.Errorf("%w: more than %d tools", ErrBadResponse, maxTools)
		}
		if p.NextCursor == "" {
			out, _ := json.Marshal(map[string]any{"resultType": "complete", "tools": tools})
			return Reply{Result: out, Bytes: total}, nil
		}
		cursor = p.NextCursor
	}
	return Reply{Bytes: total}, fmt.Errorf("%w: pagination exceeds %d pages", ErrBadResponse, maxPages)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// header values that do not travel as they are (a tool name with a non-ASCII letter) use the Base64 form of the
// 2026-07-28 transport, as the gateway's client does.
func headerValue(v string) string {
	plain := v == strings.TrimSpace(v) && !strings.HasPrefix(v, "=?base64?")
	for i := 0; plain && i < len(v); i++ {
		plain = v[i] >= 0x20 && v[i] < 0x7f
	}
	if plain {
		return v
	}
	return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(v)) + "?="
}

// do sends one request and returns its result object and how many bytes of the answer were read.
func (c *Client) do(ctx context.Context, token, method, name string, params map[string]json.RawMessage, extra http.Header) (json.RawMessage, int64, error) {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": json.Number(requestID), "method": method, "params": params})
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	h := req.Header
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json, text/event-stream")
	h.Set("MCP-Protocol-Version", mcp.ProtocolVersion)
	h.Set("Mcp-Method", method)
	if name != "" {
		h.Set("Mcp-Name", headerValue(name))
	}
	h.Set("User-Agent", userAgent)
	for k, vs := range extra {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), paramPrefix) && len(vs) == 1 {
			h.Set(k, vs[0])
		}
	}
	if token != "" {
		h.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// The error of the HTTP client names the address and may name the proxy; the caller logs a reason from the
		// sentinel, and the address is the operator's own configuration.
		return nil, 0, fmt.Errorf("%w: %w", ErrUnreachable, unwrapURL(err))
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, 0, ErrRedirect
	case resp.StatusCode == http.StatusUnauthorized:
		// nothing of the body is read: a 401 is the third party saying the token is not (or no longer) good, and what it
		// adds is for B2's discovery, which asks for it itself
		return nil, 0, statusError(resp)
	}
	res, read, err := c.read(resp)
	var rpc *RPCError
	switch {
	case errors.As(err, &rpc), errors.Is(err, ErrTooLarge), errors.Is(err, ErrReverse):
		return nil, read, err // what the third party said, or what it did, is the answer whatever the status
	case resp.StatusCode != http.StatusOK:
		return nil, read, statusError(resp)
	case err != nil:
		return nil, read, err
	}
	return res, read, nil
}

func statusError(resp *http.Response) error {
	ch := resp.Header.Get("WWW-Authenticate")
	if len(ch) > maxChallenge {
		ch = ch[:maxChallenge]
	}
	return &StatusError{Status: resp.StatusCode, Challenge: ch}
}

// unwrapURL removes the address from the error of the HTTP client, which wraps the cause in a *url.Error that repeats it.
func unwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
