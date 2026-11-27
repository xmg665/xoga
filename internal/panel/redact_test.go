package panel

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestRedactErrHidesKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://panel.example/mod_mu/users?key=SECRET123&node_id=1&token=TOK", nil)
	_, err := http.DefaultClient.Do(req)
	if err == nil {
		t.Fatal("expected error")
	}
	got := redactErr(err).Error()
	if strings.Contains(got, "SECRET123") || strings.Contains(got, "TOK") {
		t.Fatalf("secret leaked: %s", got)
	}
	if !strings.Contains(got, "node_id=1") {
		t.Fatalf("non-secret params lost: %s", got)
	}
}
