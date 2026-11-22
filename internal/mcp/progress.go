package mcp

import (
	"encoding/json"
	"strings"
)

// maxProgressToken bounds the progress token, a value the client makes up and the third party must repeat
// (idp-mcp internal/gateway external.go).
const maxProgressToken = 128

// ValidProgressToken accepts a string of at most 128 bytes without control line breaks, or an integer: the same rule
// the gateway applies before it forwards one to an external target, applied again here because this is the hop where
// it is forwarded to the third party.
func ValidProgressToken(raw json.RawMessage) bool {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return len(s) <= maxProgressToken && !strings.ContainsAny(s, "\x00\r\n")
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil && len(n) < 20 {
		_, err := n.Int64()
		return err == nil
	}
	return false
}
