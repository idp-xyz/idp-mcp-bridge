package upstream

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

// Mcp-Param-* headers (MCP 2026-07-28, SEP-2243): a tool may declare in its input schema that some arguments are mirrored into request
// headers, with the annotation `x-mcp-header` on a property. A client that knows the tool's definition computes those headers from
// the call's arguments; a server that declared them may reject a call that lacks them. The bridge is that client for the third party
// (ADR-0001 D34). It computes them from the arguments and from the definition it last listed, never copies one from the gateway's
// request, and sends none for a tool whose definition it does not have or finds invalid.
//
// The rules are the specification's as the official SDK's client (mcp/shared/inbound.py) and idp-mcp's codec
// (internal/server/protocol.go) apply them: the annotation is valid only on a property reachable from the schema's root through
// `properties` alone, names a token (RFC 9110), is on a string, integer or boolean property (never number: its text is not
// portable), and is unique case-insensitively; a tool with any invalid annotation has none. A value that is missing or null gets no
// header; a boolean is true or false; a value that is not plain printable ASCII without edge spaces is sent in the Base64 form.

// Bounds, idp-mcp's for the headers it forwards (internal/server MaxParamHeaders and the like).
const (
	MaxParamHeaders     = 16
	MaxParamHeaderName  = 128  // bytes after the prefix
	MaxParamHeaderValue = 1024 // bytes as sent, Base64 form included
	paramPrefix         = "Mcp-Param-"
	xMCPHeader          = "x-mcp-header"
)

// ErrParamTooLarge: an argument that a tool mirrors into a header does not fit the bounds. The call is refused rather than sent with
// some of its headers missing, which would make the third party reject it for a reason nobody can see (idp-mcp does the same).
var ErrParamTooLarge = errors.New("an argument that goes in a header is too long or there are too many")

var tokenRE = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

// ParamField is one mirrored argument: the path of `properties` keys to it and the header token.
type ParamField struct {
	Path   []string
	Header string
}

// ParamSpec is the headers a tool declares; empty for a tool that declares none or whose annotations are invalid.
type ParamSpec []ParamField

// the applicators whose values are schemas off the pure `properties` chain (JSON Schema 2020-12); instance data and $ref are not entered
var (
	subSingle = map[string]bool{"items": true, "contains": true, "unevaluatedItems": true, "additionalProperties": true, "propertyNames": true,
		"unevaluatedProperties": true, "not": true, "if": true, "then": true, "else": true, "contentSchema": true}
	subList = map[string]bool{"allOf": true, "anyOf": true, "oneOf": true, "prefixItems": true}
	subMap  = map[string]bool{"patternProperties": true, "dependentSchemas": true, "$defs": true, "definitions": true}
)

type pos struct {
	path   []string
	onPath bool // reached from the root by `properties` keys alone
	node   any
}

// ParseParamSpec reads a tool's input schema. reason is "" if it is fine (spec may be empty), else why the annotations are invalid;
// a tool with an invalid annotation gets no headers at all, as a client of 2026-07-28 must drop such a tool.
func ParseParamSpec(schema json.RawMessage) (spec ParamSpec, reason string) {
	if len(bytes.TrimSpace(schema)) == 0 {
		return nil, ""
	}
	dec := json.NewDecoder(bytes.NewReader(schema))
	dec.UseNumber()
	var root any
	if dec.Decode(&root) != nil {
		return nil, ""
	}
	seen := map[string]bool{}
	stack := []pos{{nil, true, root}}
	for steps := 0; len(stack) > 0; steps++ {
		if steps > 100000 {
			return nil, "the schema is too large to read"
		}
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		m, ok := p.node.(map[string]any)
		if !ok {
			continue
		}
		if raw, has := m[xMCPHeader]; has {
			tok, isStr := raw.(string)
			typ, _ := m["type"].(string)
			switch {
			case !p.onPath || len(p.path) == 0:
				return nil, xMCPHeader + " at a position that is not a property reachable through `properties`"
			case !isStr || !tokenRE.MatchString(tok):
				return nil, xMCPHeader + " is not a token"
			case typ != "string" && typ != "integer" && typ != "boolean":
				return nil, xMCPHeader + " is only for string, integer and boolean properties"
			case seen[strings.ToLower(tok)]:
				return nil, xMCPHeader + " names are not unique"
			}
			seen[strings.ToLower(tok)] = true
			spec = append(spec, ParamField{Path: append([]string(nil), p.path...), Header: tok})
		}
		for kw, v := range m {
			switch {
			case kw == "properties":
				if props, ok := v.(map[string]any); ok {
					for name, sub := range props {
						path := []string(nil)
						if p.onPath {
							path = append(append([]string(nil), p.path...), name)
						}
						stack = append(stack, pos{path, p.onPath, sub})
					}
				}
			case subSingle[kw]:
				stack = append(stack, pos{nil, false, v})
			case subList[kw]:
				if l, ok := v.([]any); ok {
					for _, sub := range l {
						stack = append(stack, pos{nil, false, sub})
					}
				}
			case subMap[kw]:
				if mm, ok := v.(map[string]any); ok {
					for _, sub := range mm {
						stack = append(stack, pos{nil, false, sub})
					}
				}
			}
		}
	}
	return spec, ""
}

// EncodeParamValue is the form to send a value in: as it is if it is plain printable ASCII without leading or trailing whitespace
// (and does not itself look like the Base64 form), else =?base64?{Base64 of the UTF-8 text}?= (idp-mcp's EncodeHeaderValue). A value
// with a line break in it, which would end the header line, is therefore never sent as it is.
func EncodeParamValue(v string) string {
	plain := v == strings.TrimSpace(v) && !strings.HasPrefix(v, "=?base64?")
	for i := 0; plain && i < len(v); i++ {
		plain = v[i] >= 0x20 && v[i] < 0x7f
	}
	if plain {
		return v
	}
	return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(v)) + "?="
}

var intRE = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// ParamHeaders computes the headers of a call from the arguments, as the spec says: nothing for a missing or null value or one that
// has no rendering (an object, an array, a number with a fraction). It returns ErrParamTooLarge if they do not fit the bounds.
func ParamHeaders(spec ParamSpec, args json.RawMessage) (http.Header, error) {
	if len(spec) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.UseNumber()
	var root any
	if dec.Decode(&root) != nil {
		return nil, nil
	}
	out := http.Header{}
	for _, f := range spec {
		var node = root
		for _, k := range f.Path {
			m, ok := node.(map[string]any)
			if !ok {
				node = nil
				break
			}
			node = m[k]
		}
		var text string
		switch v := node.(type) {
		case string:
			text = v
		case bool:
			text = map[bool]string{true: "true", false: "false"}[v]
		case json.Number:
			if !intRE.MatchString(v.String()) {
				continue
			}
			text = v.String()
		default:
			continue // missing, null, or no rendering
		}
		if len(f.Header) > MaxParamHeaderName {
			return nil, ErrParamTooLarge
		}
		enc := EncodeParamValue(text)
		if len(out) >= MaxParamHeaders || len(enc) > MaxParamHeaderValue {
			return nil, ErrParamTooLarge
		}
		out.Set(paramPrefix+f.Header, enc)
	}
	return out, nil
}
