package upstream

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// Namespace is the prefix of every key only the bridge, the gateway and the platform may set on a result or a tool
// (io.idp.telos/external, io.idp.telos/authorizationRequired, io.idp.telos/caller ...). A third party that sets one
// would be telling the platform something about itself that the platform decides (idp-mcp ADR-0001 D51 h; ADR-0001 D11).
const Namespace = "io.idp.telos/"

// Sanitize returns the result object with every key of the namespace removed, at any depth, whatever the value; it
// also adds resultType "complete" if there is none, and reports the result's isError. The result is decoded and written
// again, so duplicate keys collapse (the last wins, as in any reader) instead of one parser seeing the key and another
// not, and numbers are kept as they were written.
func Sanitize(raw json.RawMessage) (json.RawMessage, bool, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, false, errors.New("the result is not an object")
	}
	strip(obj)
	if _, ok := obj["resultType"]; !ok {
		obj["resultType"] = "complete"
	}
	isErr, _ := obj["isError"].(bool)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return nil, false, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), isErr, nil
}

func strip(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if strings.HasPrefix(k, Namespace) {
				delete(x, k)
				continue
			}
			strip(e)
		}
	case []any:
		for _, e := range x {
			strip(e)
		}
	}
}
