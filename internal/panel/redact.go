package panel

import (
	"errors"
	"net/url"
	"strings"
)

var secretQueryKeys = []string{"key", "token", "mukey", "webapi_key"}

// redactURL masks secret query parameters so panel keys never reach logs.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid url>"
	}
	q := u.Query()
	changed := false
	for _, k := range secretQueryKeys {
		if q.Has(k) {
			q.Set(k, "***")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// redactQuerySecrets masks secret query parameters (`?key=...`, `&token=...`, etc.)
// that may be echoed verbatim inside panel/reverse-proxy error response bodies.
func redactQuerySecrets(s string) string {
	if !strings.ContainsAny(s, "?&") {
		return s
	}
	lower := strings.ToLower(s)
	var b strings.Builder
	wrote := false
	i := 0
	for i < len(s) {
		if s[i] == '?' || s[i] == '&' {
			matchedLen := 0
			for _, k := range secretQueryKeys {
				need := k + "="
				if i+1+len(need) <= len(lower) && lower[i+1:i+1+len(need)] == need {
					matchedLen = len(need)
					break
				}
			}
			if matchedLen > 0 {
				if !wrote {
					b.Grow(len(s))
					b.WriteString(s[:i])
					wrote = true
				}
				b.WriteString(s[i : i+1+matchedLen])
				b.WriteString("***")
				j := i + 1 + matchedLen
				for j < len(s) {
					c := s[j]
					if c == '&' || c == '#' || c <= ' ' || c == '"' || c == '\'' || c == '<' || c == '>' || c == ')' || c == ']' {
						break
					}
					j++
				}
				i = j
				continue
			}
		}
		if wrote {
			b.WriteByte(s[i])
		}
		i++
	}
	if !wrote {
		return s
	}
	return b.String()
}

// redactErr rewrites *url.Error (returned by http.Client.Do) to hide secrets in its URL.
func redactErr(err error) error {
	var ue *url.Error
	if err == nil || !errors.As(err, &ue) {
		return err
	}
	return &url.Error{Op: ue.Op, URL: redactURL(ue.URL), Err: ue.Err}
}
