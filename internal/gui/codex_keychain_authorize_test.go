package gui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCodexKeychainAuthorizationRoute(t *testing.T) {
	sandboxHome(t)
	old := authorizeCodexKeychain
	t.Cleanup(func() { authorizeCodexKeychain = old })
	mux := http.NewServeMux()
	providerRoutes(mux, nil)
	for _, refused := range []bool{false, true} {
		authorizeCodexKeychain = func(ctx context.Context, user string) error {
			if user != "selected@example.invalid" {
				t.Fatalf("authorized %q", user)
			}
			if refused {
				return errors.New("choose Always Allow")
			}
			return nil
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("POST", "/api/codex/keychain/authorize", strings.NewReader(`{"user":"selected@example.invalid"}`)))
		if refused {
			if w.Code != 400 || !strings.Contains(w.Body.String(), "choose Always Allow") {
				t.Fatalf("refused: %d %s", w.Code, w.Body)
			}
		} else if w.Code != 200 || !strings.Contains(w.Body.String(), `"authorized":true`) {
			t.Fatalf("authorized: %d %s", w.Code, w.Body)
		}
	}
}

func TestCodexKeychainAuthorizationCancelsWithRequest(t *testing.T) {
	sandboxHome(t)
	old := authorizeCodexKeychain
	t.Cleanup(func() { authorizeCodexKeychain = old })
	started := make(chan struct{})
	authorizeCodexKeychain = func(ctx context.Context, _ string) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	mux := http.NewServeMux()
	providerRoutes(mux, nil)
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest("POST", "/api/codex/keychain/authorize", strings.NewReader(`{"user":"selected@example.invalid"}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { mux.ServeHTTP(w, r); close(done) }()
	<-started
	cancel()
	<-done
	if w.Code != 400 {
		t.Fatalf("cancelled: %d %s", w.Code, w.Body)
	}
}
