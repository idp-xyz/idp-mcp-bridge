package upstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func spec(t *testing.T, schema string) ParamSpec {
	t.Helper()
	s, reason := ParseParamSpec(json.RawMessage(schema))
	if reason != "" {
		t.Fatalf("%s", reason)
	}
	return s
}

func TestAToolDeclaresItsHeadersWithXMCPHeaderOnPropertiesReachedThroughProperties(t *testing.T) {
	s := spec(t, `{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},"n":{"type":"integer","x-mcp-header":"N"},"f":{"type":"boolean","x-mcp-header":"F"},
	"q":{"type":"string"},"deep":{"type":"object","properties":{"a":{"type":"object","properties":{"b":{"type":"string","x-mcp-header":"Deep-B"}}}}}}}`)
	got := map[string]string{}
	for _, f := range s {
		got[f.Header] = strings.Join(f.Path, ".")
	}
	if len(got) != 4 || got["Region"] != "region" || got["N"] != "n" || got["F"] != "f" || got["Deep-B"] != "deep.a.b" {
		t.Fatalf("%v", got)
	}
	if s, r := ParseParamSpec(nil); s != nil || r != "" {
		t.Fatal("a tool with no schema declares nothing")
	}
}

// A tool with any invalid annotation has none at all, as a client of 2026-07-28 drops such a tool.
func TestAToolWithAnInvalidAnnotationHasNoHeaders(t *testing.T) {
	for name, schema := range map[string]string{
		"a number (its text is not portable)": `{"properties":{"x":{"type":"number","x-mcp-header":"X"}}}`,
		"an object":                           `{"properties":{"x":{"type":"object","x-mcp-header":"X"}}}`,
		"no type":                             `{"properties":{"x":{"x-mcp-header":"X"}}}`,
		"a type list":                         `{"properties":{"x":{"type":["string","null"],"x-mcp-header":"X"}}}`,
		"not a string":                        `{"properties":{"x":{"type":"string","x-mcp-header":5}}}`,
		"an empty name":                       `{"properties":{"x":{"type":"string","x-mcp-header":""}}}`,
		"a name that is not a token":          `{"properties":{"x":{"type":"string","x-mcp-header":"A B"}}}`,
		"a name with a colon":                 `{"properties":{"x":{"type":"string","x-mcp-header":"A:B"}}}`,
		"a name with a line break":            `{"properties":{"x":{"type":"string","x-mcp-header":"A\r\nX-Evil"}}}`,
		"names that differ in case only":      `{"properties":{"x":{"type":"string","x-mcp-header":"Region"},"y":{"type":"string","x-mcp-header":"REGION"}}}`,
		"on the root":                         `{"type":"string","x-mcp-header":"Root"}`,
		"inside anyOf":                        `{"properties":{"x":{"anyOf":[{"type":"string","x-mcp-header":"X"}]}}}`,
		"inside items":                        `{"properties":{"x":{"type":"array","items":{"type":"string","x-mcp-header":"X"}}}}`,
		"under patternProperties":             `{"patternProperties":{"^a":{"type":"string","x-mcp-header":"X"}}}`,
		"under $defs":                         `{"$defs":{"d":{"type":"string","x-mcp-header":"X"}}}`,
		"one good and one bad":                `{"properties":{"a":{"type":"string","x-mcp-header":"A"},"b":{"type":"number","x-mcp-header":"B"}}}`,
	} {
		if s, reason := ParseParamSpec(json.RawMessage(schema)); reason == "" {
			t.Errorf("%s: accepted, %v", name, s)
		}
	}
	// the data of a schema is not a schema: an enum or a default that looks like an annotation is not one
	if s := spec(t, `{"properties":{"x":{"type":"string","default":{"x-mcp-header":"Y"},"enum":[{"x-mcp-header":"Z"}]}}}`); len(s) != 0 {
		t.Fatalf("%v", s)
	}
}

func TestTheHeadersAreComputedFromTheArgumentsAsTheSpecificationSays(t *testing.T) {
	s := spec(t, `{"properties":{"region":{"type":"string","x-mcp-header":"Region"},"n":{"type":"integer","x-mcp-header":"N"},"f":{"type":"boolean","x-mcp-header":"F"},
	"nested":{"properties":{"a":{"type":"string","x-mcp-header":"Nested-A"}}}}}`)
	h, err := ParamHeaders(s, json.RawMessage(`{"region":"eu-west","n":-12,"f":false,"nested":{"a":"deep"},"other":"x"}`))
	if err != nil || h.Get("Mcp-Param-Region") != "eu-west" || h.Get("Mcp-Param-N") != "-12" || h.Get("Mcp-Param-F") != "false" || h.Get("Mcp-Param-Nested-A") != "deep" || len(h) != 4 {
		t.Fatalf("%v %v", h, err)
	}
	// missing, null, and values that have no rendering get no header
	for name, args := range map[string]string{"missing": `{}`, "null": `{"region":null,"n":null}`, "a fraction": `{"n":1.5}`, "an exponent": `{"n":1e3}`, "a leading zero": `{"n":007}`,
		"an object": `{"region":{"a":1}}`, "an array": `{"region":["a"],"n":[1]}`, "the path is not an object": `{"nested":"x"}`, "not JSON": `nope`} {
		h, err := ParamHeaders(s, json.RawMessage(args))
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
		for k := range h {
			if k != "Mcp-Param-Region" && k != "Mcp-Param-N" {
				t.Errorf("%s: %s", name, k)
			}
		}
	}
	if h, _ := ParamHeaders(s, json.RawMessage(`{"n":1.5,"region":{"a":1}}`)); len(h) != 0 {
		t.Fatalf("%v", h)
	}
	// a large integer as written, not rounded
	if h, _ := ParamHeaders(s, json.RawMessage(`{"n":12345678901234567890}`)); h.Get("Mcp-Param-N") != "12345678901234567890" {
		t.Fatalf("%v", h)
	}
	if h, err := ParamHeaders(nil, json.RawMessage(`{"region":"x"}`)); h != nil || err != nil {
		t.Fatal("a tool with no headers gets none")
	}
}

// A value that would end the header line and start another is sent in the Base64 form, and nothing that is not printable ASCII is
// ever sent as it is.
func TestAValueThatWouldInjectAHeaderLineIsSentInTheBase64Form(t *testing.T) {
	s := spec(t, `{"properties":{"region":{"type":"string","x-mcp-header":"Region"}}}`)
	for _, v := range []string{"eu\r\nX-Evil: 1", "eu\nX-Evil: 1", "eu\rX", "eu\x00x", "\tleading tab", " leading space", "trailing space ", "café", "=?base64?QQ==?=", "del\x7fx", "line sep"} {
		raw, _ := json.Marshal(map[string]string{"region": v})
		h, err := ParamHeaders(s, raw)
		got := h.Get("Mcp-Param-Region")
		if err != nil || !strings.HasPrefix(got, "=?base64?") || !strings.HasSuffix(got, "?=") || strings.ContainsAny(got, "\r\n\x00") {
			t.Errorf("%q: %q %v", v, got, err)
			continue
		}
		dec, derr := base64.StdEncoding.DecodeString(got[len("=?base64?") : len(got)-2])
		if derr != nil || string(dec) != v {
			t.Errorf("%q does not round-trip: %q", v, dec)
		}
	}
	// and what is plain stays plain
	raw, _ := json.Marshal(map[string]string{"region": "eu-west-1 (primary)"})
	if h, _ := ParamHeaders(s, raw); h.Get("Mcp-Param-Region") != "eu-west-1 (primary)" {
		t.Fatalf("%v", h)
	}
}

func TestHeadersThatDoNotFitTheBoundsRefuseTheCallAndNothingIsTruncated(t *testing.T) {
	s := spec(t, `{"properties":{"a":{"type":"string","x-mcp-header":"A"}}}`)
	long := `{"a":"` + strings.Repeat("x", MaxParamHeaderValue+1) + `"}`
	if _, err := ParamHeaders(s, json.RawMessage(long)); err != ErrParamTooLarge {
		t.Fatalf("a value over the bound: %v", err)
	}
	if h, err := ParamHeaders(s, json.RawMessage(`{"a":"`+strings.Repeat("x", MaxParamHeaderValue)+`"}`)); err != nil || len(h) != 1 {
		t.Fatalf("a value at the bound: %v", err)
	}
	// the bound is on what is sent: a value that is short and needs the Base64 form may be over it
	if _, err := ParamHeaders(s, json.RawMessage(`{"a":"`+strings.Repeat("é", 400)+`"}`)); err != ErrParamTooLarge {
		t.Fatalf("a value that is over the bound once encoded: %v", err)
	}
	var props []string
	for i := 0; i <= MaxParamHeaders; i++ {
		props = append(props, `"p`+string(rune('a'+i))+`":{"type":"string","x-mcp-header":"H`+string(rune('a'+i))+`"}`)
	}
	many := spec(t, `{"properties":{`+strings.Join(props, ",")+`}}`)
	var args []string
	for i := 0; i <= MaxParamHeaders; i++ {
		args = append(args, `"p`+string(rune('a'+i))+`":"v"`)
	}
	if _, err := ParamHeaders(many, json.RawMessage(`{`+strings.Join(args, ",")+`}`)); err != ErrParamTooLarge {
		t.Fatalf("more than %d headers: %v", MaxParamHeaders, err)
	}
	longName := spec(t, `{"properties":{"a":{"type":"string","x-mcp-header":"`+strings.Repeat("N", MaxParamHeaderName+1)+`"}}}`)
	if _, err := ParamHeaders(longName, json.RawMessage(`{"a":"v"}`)); err != ErrParamTooLarge {
		t.Fatalf("a name over the bound: %v", err)
	}
}

// Only the Mcp-Param-* family goes out through the extra headers; anything else a caller of the client puts there is dropped.
func TestOnlyMcpParamHeadersGoOutThroughTheExtraHeaders(t *testing.T) {
	var got http.Header
	c := serve(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, final)
	})
	extra := http.Header{"Mcp-Param-Region": {"eu"}, "Authorization": {"Bearer stolen"}, "X-Forwarded-For": {"10.0.0.1"}, "Traceparent": {"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
		"Mcp-Param-Two": {"a", "b"}, "Cookie": {"s=1"}}
	if _, err := c.CallToolWithHeaders(context.Background(), "", "t", nil, nil, extra); err != nil {
		t.Fatal(err)
	}
	if got.Get("Mcp-Param-Region") != "eu" || got.Get("Authorization") != "" || got.Get("X-Forwarded-For") != "" || got.Get("Traceparent") != "" || got.Get("Cookie") != "" {
		t.Fatalf("%v", got)
	}
	if got.Get("Mcp-Param-Two") != "" {
		t.Fatalf("a header with two values was sent: %v", got)
	}
}
