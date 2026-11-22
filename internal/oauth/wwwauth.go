package oauth

import "strings"

// Challenge is the parameters of the first Bearer challenge of a WWW-Authenticate header (RFC 9110 section 11.6.1, RFC 6750
// section 3, RFC 9728 section 5.1): error, scope and resource_metadata are what the bridge reads.
type Challenge map[string]string

// ParseChallenge reads a Bearer challenge: auth-param = token "=" ( token / quoted-string ), separated by commas, quoted
// strings with backslash escapes. A header of another scheme, or no header, gives nil. Other challenges after the Bearer one
// are ignored, and a value that is cut off (the header is bounded by the client) ends the parse with what was read.
func ParseChallenge(h string) Challenge {
	h = strings.TrimSpace(h)
	if len(h) < 6 || !strings.EqualFold(h[:6], "bearer") || (len(h) > 6 && h[6] != ' ' && h[6] != '\t') {
		return nil
	}
	h = h[6:]
	out := Challenge{}
	for {
		h = strings.TrimLeft(h, " \t,")
		eq := strings.IndexByte(h, '=')
		sp := strings.IndexAny(h, " \t,")
		if h == "" || eq < 0 || (sp >= 0 && sp < eq) {
			return out // end, or the next challenge's scheme name
		}
		name := strings.ToLower(strings.TrimSpace(h[:eq]))
		h = h[eq+1:]
		var val string
		if strings.HasPrefix(h, `"`) {
			var b strings.Builder
			i := 1
			closed := false
			for ; i < len(h); i++ {
				if h[i] == '\\' && i+1 < len(h) {
					i++
					b.WriteByte(h[i])
					continue
				}
				if h[i] == '"' {
					closed = true
					break
				}
				b.WriteByte(h[i])
			}
			if !closed {
				return out
			}
			val, h = b.String(), h[i+1:]
		} else {
			end := strings.IndexAny(h, ", \t")
			if end < 0 {
				end = len(h)
			}
			val, h = h[:end], h[end:]
		}
		if _, dup := out[name]; !dup {
			out[name] = val
		}
	}
}
