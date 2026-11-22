package upstream

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

// verdict of one message of the third party's answer (idp-mcp internal/gateway/external.go classify, adapted: the
// bridge keeps the result, the gateway relays it).
type verdict int

const (
	vFinal   verdict = iota // the response to this request
	vDrop                   // a notification: progress included, which this endpoint does not relay (ADR-0001 D10)
	vReverse                // a request from the server to the client, or a result that asks for one
	vBad                    // not a message of this call
)

// reverseMethods names the requests a server may send a client; only these are put in a message, so that a method
// name the third party made up is not.
var reverseMethods = map[string]bool{"sampling/createMessage": true, "elicitation/create": true, "roots/list": true, "ping": true}

func reverse(method string) *ReverseError {
	if !reverseMethods[method] {
		method = "an unknown method"
	}
	return &ReverseError{Reason: "the service sent the client a request (" + method + "); a third party may not ask the client for anything"}
}

// classify says what a message is. On vFinal it returns the result object, or the third party's error.
func classify(raw []byte) (v verdict, result json.RawMessage, err error) {
	var m struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Result  json.RawMessage `json:"result"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &m) != nil || m.JSONRPC != "2.0" {
		return vBad, nil, nil
	}
	id := bytes.TrimSpace(m.ID)
	hasID := len(id) > 0 && string(id) != "null"
	if m.Method != "" {
		if hasID {
			return vReverse, nil, reverse(m.Method)
		}
		return vDrop, nil, nil
	}
	if !hasID || string(id) != requestID {
		return vBad, nil, nil
	}
	if m.Error != nil {
		msg := m.Error.Message
		if len(msg) > maxRPCMessage {
			msg = strings.ToValidUTF8(msg[:maxRPCMessage], "")
		}
		return vFinal, nil, &RPCError{Code: m.Error.Code, Message: msg}
	}
	trimmed := bytes.TrimSpace(m.Result)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return vBad, nil, nil
	}
	var rt struct {
		ResultType string `json:"resultType"`
	}
	_ = json.Unmarshal(trimmed, &rt)
	switch rt.ResultType {
	case "input_required":
		// the 2026-07-28 form of a server asking the client for sampling, elicitation or roots
		return vReverse, nil, &ReverseError{Reason: "the service answered with a request for input from the client (input_required); a third party may not ask the client for anything"}
	case "task":
		return vReverse, nil, &ReverseError{Reason: "the service answered with a task, which was not asked for and which the bridge does not route"}
	case "", "complete":
	default:
		return vBad, nil, nil
	}
	return vFinal, trimmed, nil
}

// read judges the answer: one JSON message or an event stream, with the limits. It returns the result object (or the
// third party's error) and the number of bytes it read.
//
// Memory: the whole of a plain answer is held, up to MaxResult bytes; of a stream one event at a time, up to the same
// number, and nothing past MaxStream bytes is read at all, comments and keep-alive lines included. So a third party
// that never stops costs the bridge one buffer and the call's time limit.
func (c *Client) read(resp *http.Response) (json.RawMessage, int64, error) {
	maxResult, maxStream := c.limits()
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch strings.ToLower(mt) {
	case "application/json":
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResult+1))
		n := int64(len(raw))
		if err != nil {
			return nil, n, fmt.Errorf("%w: %v", ErrBadResponse, unwrapURL(err))
		}
		if n > maxResult {
			return nil, n, &LimitError{Limit: maxResult}
		}
		return finish(raw, n)
	case "text/event-stream":
	default:
		return nil, 0, fmt.Errorf("%w: content type %q", ErrBadResponse, mt)
	}

	rd := bufio.NewReaderSize(resp.Body, 16<<10)
	var total int64
	var data []byte
	for {
		// one line, held up to the size of one event
		var line []byte
		for {
			chunk, more, err := rd.ReadLine()
			total += int64(len(chunk)) + 1
			if total > maxStream {
				return nil, total, &LimitError{Limit: maxStream, Stream: true}
			}
			if int64(len(line)+len(chunk)) > maxResult {
				return nil, total, &LimitError{Limit: maxResult}
			}
			line = append(line, chunk...)
			if err != nil { // the stream ended (or the call's time ran out) before the answer
				return nil, total, fmt.Errorf("%w: the stream ended without an answer", ErrBadResponse)
			}
			if !more {
				break
			}
		}
		switch {
		case bytes.HasPrefix(line, []byte("data:")):
			part := bytes.TrimPrefix(bytes.TrimPrefix(line, []byte("data:")), []byte(" "))
			if int64(len(data)+len(part)+1) > maxResult {
				return nil, total, &LimitError{Limit: maxResult}
			}
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, part...)
		case len(line) == 0 && len(data) > 0:
			var compact bytes.Buffer
			ok := json.Compact(&compact, data) == nil
			data = data[:0]
			if !ok {
				continue
			}
			v, _, _ := classify(compact.Bytes())
			if v == vDrop || v == vBad {
				continue // a notification, or something that is not this call's: not relayed, not an answer
			}
			return finish(compact.Bytes(), total)
		}
	}
}

func finish(raw []byte, n int64) (json.RawMessage, int64, error) {
	v, res, err := classify(raw)
	switch v {
	case vReverse:
		return nil, n, err
	case vFinal:
		if err != nil {
			return nil, n, err
		}
		return res, n, nil
	}
	return nil, n, fmt.Errorf("%w: not a response to the request", ErrBadResponse)
}
