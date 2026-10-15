//go:build darwin

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/yetone/magpie/internal/testenv"
)

func TestCodexKeychainSource(t *testing.T) {
	home, _ := codexHome(t, `{"auth_mode":"chatgpt","tokens":{"access_token":"fixture"}}`, "cli_auth_credentials_store = \"keyring\"\n")
	dir := filepath.Join(home, ".codex")
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(canonical))
	account := "cli|" + hex.EncodeToString(sum[:])[:16]
	item := filepath.Join(home, "fixture-item")
	b, err := os.ReadFile(filepath.Join(dir, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(item, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "auth.json")); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(home, "bin")
	os.MkdirAll(bin, 0o700)
	testenv.Program(t, filepath.Join(bin, "security"), `#!/bin/sh
[ "$1" = find-generic-password ] || exit 1
[ "$3" = 'Codex Auth' ] || exit 44
[ "$5" = '`+account+`' ] || exit 44
cat '`+item+`'
`)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if !codexChatGPT(dir) {
		t.Fatal("Codex wiring ignored the Keychain ChatGPT login")
	}
	if got := codex(home).Source(); got != "chatgpt" {
		t.Fatalf("agent source = %q, want chatgpt", got)
	}
}
