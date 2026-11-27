package panel

import (
	"errors"
	"net/url"
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

// redactErr rewrites *url.Error (returned by http.Client.Do) to hide secrets in its URL.
func redactErr(err error) error {
	var ue *url.Error
	if err == nil || !errors.As(err, &ue) {
		return err
	}
	return &url.Error{Op: ue.Op, URL: redactURL(ue.URL), Err: ue.Err}
}
