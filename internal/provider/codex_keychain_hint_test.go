package provider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #2367: the authorization hint follows the store actually read, not the
// word "auto" in config.toml. No extra secret read is needed for the hint.
func TestCodexAccountKeychainHint(t *testing.T) {
	for _, tc := range []struct {
		name, mode             string
		item, refused, secrets bool
		unavailable, want      bool
	}{
		{name: "file beside an item", mode: "file", item: true},
		{name: "keyring", mode: "keyring", item: true, want: true},
		{name: "auto item before file", mode: "auto", item: true, want: true},
		{name: "auto without item", mode: "auto"},
		{name: "auto refused falls back to file", mode: "auto", item: true, refused: true},
		{name: "auto encrypted store", mode: "auto", item: true, secrets: true},
		{name: "auto on another system", mode: "auto", item: true, unavailable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := signIn(t)
			dir := filepath.Join(home, ".codex")
			b, err := os.ReadFile(filepath.Join(dir, "auth.json"))
			if err != nil {
				t.Fatal(err)
			}
			k := &fakeKeychain{items: map[string][]byte{}}
			if tc.item {
				k.set(codexKeychainAccount(dir), b)
			}
			if tc.refused {
				k.findErr = errKeychainRefused
			}
			codexKeychain, codexKeychainHere = k, !tc.unavailable
			old := secretAuthStorageDefault
			secretAuthStorageDefault = tc.secrets
			t.Cleanup(func() { secretAuthStorageDefault = old })
			if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("cli_auth_credentials_store = \""+tc.mode+"\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				p, ok := codexAccount(home)
				if !ok || p.Account.Keychain != tc.want {
					t.Fatalf("keychain authorization hint = %+v, provider found %v; want %v", p.Account, ok, tc.want)
				}
				out, err := json.Marshal(p.Account)
				if err != nil || strings.Contains(string(out), `"keychain":true`) != tc.want {
					t.Fatalf("account JSON has wrong keychain hint: %s (%v)", out, err)
				}
			}
			finds, _ := k.counts()
			wantFinds := 1
			if tc.mode == "file" || tc.secrets || tc.unavailable || !tc.item {
				wantFinds = 0
			}
			if finds != wantFinds {
				t.Fatalf("hint caused %d secret reads, want %d", finds, wantFinds)
			}
		})
	}
}
