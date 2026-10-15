//go:build darwin

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/filememo"
	"github.com/yetone/magpie/internal/testenv"
)

// security answers only for this fixture's canonical CODEX_HOME; it never
// reaches the machine's Keychain. Its writes are visible to later reads,
// so the test follows discovery, rotation, switching and logout end to end.
func codexKeychainFixture(t *testing.T, home string) string {
	t.Helper()
	dir := filepath.Join(home, ".codex")
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(canonical))
	account := "cli|" + hex.EncodeToString(sum[:])[:16]
	bin := filepath.Join(home, "bin")
	os.MkdirAll(bin, 0o700)
	item := filepath.Join(bin, "codex-item")
	b, err := os.ReadFile(filepath.Join(dir, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(item, b, 0o600); err != nil {
		t.Fatal(err)
	}
	testenv.Program(t, filepath.Join(bin, "security"), `#!/bin/sh
op="$1"; shift
service=""; account=""; value=""
while [ "$#" -gt 0 ]; do
 case "$1" in
 -s) service="$2"; shift;;
 -a) account="$2"; shift;;
 -w) if [ "$#" -gt 1 ]; then value="$2"; shift; fi;;
 esac
 shift
done
[ "$service" = 'Codex Auth' ] || exit 44
[ "$account" = '`+account+`' ] || exit 44
case "$op" in
 find-generic-password) [ -f '`+item+`' ] || exit 44; cat '`+item+`';;
 add-generic-password) printf '%s' "$value" > '`+item+`';;
 delete-generic-password) rm -f '`+item+`';;
 *) exit 1;;
esac
`)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("cli_auth_credentials_store = \"keyring\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "auth.json")); err != nil {
		t.Fatal(err)
	}
	filememo.Forget()
	return item
}

func TestCodexKeychainProviderLifecycle(t *testing.T) {
	home := signIn(t)
	rememberLogins(true)
	codexSignIn(t, home, "work@example.com", "r-work")
	rememberLogins(true)
	item := codexKeychainFixture(t, home)
	if p, ok := codexAccount(home); !ok || p.Account.User != "work@example.com" {
		t.Fatal("valid Keychain login is missing from providers")
	}
	if _, active := loginUsers(Logins("codex")); active != "work@example.com" {
		t.Fatal("Keychain login not recognized as the active account")
	}
	if got := savedButSignedOut(); len(got) != 0 {
		t.Fatal("saved accounts hidden despite a valid Keychain login")
	}
	if ids := currentSessionIdentities(filepath.Join(home, ".codex")); len(ids) == 0 || ids[0].User != "work@example.com" {
		t.Fatal("current session identity ignored Keychain")
	}
	// Expire only the fake token: the refresh goes to the local fake vendor.
	b, _ := os.ReadFile(item)
	var raw map[string]any
	json.Unmarshal(b, &raw)
	raw["future_field"] = map[string]any{"keep": true}
	until := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	raw["tokens"].(map[string]any)["id_token"] = fakeJWT(map[string]any{"email": "work@example.com", "https://api.openai.com/auth": map[string]any{"chatgpt_plan_type": "plus", "chatgpt_subscription_active_until": until.Format(time.RFC3339)}})
	raw["tokens"].(map[string]any)["access_token"] = fakeJWT(map[string]any{"exp": float64(time.Now().Add(-time.Minute).Unix())})
	writeFile(t, item, raw)
	fakeCodexRefresh(t)
	if _, _, err := codexToken(context.Background(), codexAuthPath()); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(item)
	if !strings.Contains(string(b), "r-work-2") || !strings.Contains(string(b), "future_field") {
		t.Fatal("refresh did not preserve and rotate the secure credential")
	}
	usage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"plan_type": "plus"})
	}))
	t.Cleanup(usage.Close)
	oldBase := CodexBase
	CodexBase = usage.URL + "/codex"
	t.Cleanup(func() { CodexBase = oldBase })
	quota := codexSubscriptionUsage(context.Background(), codexAuthPath())
	if quota.Error != "" || quota.Until == nil || !quota.Until.Equal(until) {
		t.Fatalf("quota omitted the Keychain login's subscription term: %s", quota.Error)
	}
	if err := SwitchLogin("codex", "me@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, active := loginUsers(Logins("codex")); active != "me@example.com" {
		t.Fatal("switch wrote a file Codex would ignore")
	}
	var switched codexAuth
	b, _ = os.ReadFile(item)
	if json.Unmarshal(b, &switched) != nil || switched.Tokens.AccountID != "acct-1" {
		t.Fatal("account switch did not reach Keychain")
	}
	if err := ForgetLogin("codex", "work@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := ForgetLogin("codex", "me@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(item); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("last-account removal left Keychain login behind")
	}
	if _, err := os.Stat(codexAuthPath()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("Keychain lifecycle created auth.json")
	}
}

func TestCodexKeychainFirstSignIn(t *testing.T) {
	home := signIn(t)
	item := codexKeychainFixture(t, home)
	login, ok := liveLogin("codex")
	if !ok {
		t.Fatal("fixture login not found")
	}
	if err := os.Remove(item); err != nil {
		t.Fatal(err)
	}
	using, err := addLogin(login)
	if err != nil || !using {
		t.Fatalf("first sign-in was not put into Codex's store: using=%v err=%v", using, err)
	}
	if _, ok := codexAccount(home); !ok {
		t.Fatal("first sign-in is not offered as a provider")
	}
	if _, err := os.Stat(codexAuthPath()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("first sign-in created a file in keyring mode")
	}
}
