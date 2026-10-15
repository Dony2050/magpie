package codexauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/filememo"
	"github.com/yetone/magpie/internal/testenv"
)

func TestMain(m *testing.M) { testenv.Main(m) }

type fakeKeychain struct {
	item        []byte
	calls       [][]string
	denied      bool
	refuseWrite bool
}

func fakeStore(t *testing.T) *fakeKeychain {
	t.Helper()
	f := &fakeKeychain{}
	old, oldSupported := runSecurity, keychainSupported
	keychainSupported = true
	runSecurity = func(args ...string) ([]byte, error) {
		f.calls = append(f.calls, append([]string(nil), args...))
		if f.denied {
			return nil, errors.New("denied: NEVER-PRINT-THIS-TOKEN")
		}
		switch args[0] {
		case "find-generic-password":
			if f.item == nil {
				return nil, fs.ErrNotExist
			}
			return bytes.Clone(f.item), nil
		case "add-generic-password":
			if f.refuseWrite {
				return nil, errors.New("refused")
			}
			f.item = []byte(args[len(args)-1])
			return nil, nil
		case "delete-generic-password":
			if f.item == nil {
				return nil, fs.ErrNotExist
			}
			f.item = nil
			return nil, nil
		}
		return nil, errors.New("unexpected command")
	}
	t.Cleanup(func() { runSecurity, keychainSupported = old, oldSupported })
	return f
}
func config(t *testing.T, home, mode string) {
	t.Helper()
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte("cli_auth_credentials_store = \""+mode+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	filememo.Forget()
}
func auth(token string) []byte {
	return []byte(`{"auth_mode":"chatgpt","tokens":{"access_token":"` + token + `"},"future":{"keep":true}}`)
}
func file(t *testing.T, home string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(home, "auth.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSelectedStore(t *testing.T) {
	for _, m := range []string{"file", "keyring", "auto"} {
		t.Run(m, func(t *testing.T) {
			f := fakeStore(t)
			h := t.TempDir()
			config(t, h, m)
			file(t, h, auth("file"))
			f.item = auth("secure")
			b, _, err := Read(h)
			if err != nil {
				t.Fatal(err)
			}
			want := auth("secure")
			if m == "file" {
				want = auth("file")
			}
			if !bytes.Equal(b, want) {
				t.Fatalf("%s selected the wrong account", m)
			}
			if m == "file" && len(f.calls) != 0 {
				t.Fatal("file mode probed Keychain")
			}
			if !ChatGPT(h) {
				t.Fatal("ChatGPT login not detected")
			}
		})
	}
}
func TestAutoFallbackAndStrictKeyring(t *testing.T) {
	f := fakeStore(t)
	h := t.TempDir()
	config(t, h, "auto")
	file(t, h, auth("fallback"))
	for _, denied := range []bool{false, true} {
		f.denied = denied
		b, _, err := Read(h)
		if err != nil || !bytes.Equal(b, auth("fallback")) {
			t.Fatal("auto did not use file fallback")
		}
	}
	config(t, h, "keyring")
	if _, _, err := Read(h); err == nil {
		t.Fatal("keyring used a stale file after a failed secure read")
	}
	if err := Save(h, auth("new")); err == nil || strings.Contains(err.Error(), "NEVER-PRINT") {
		t.Fatal("failed read overwrote credentials or leaked stderr")
	}
	if b, _ := os.ReadFile(filepath.Join(h, "auth.json")); !bytes.Equal(b, auth("fallback")) {
		t.Fatal("failed secure read changed fallback")
	}
}
func TestRotationStaysInKeychain(t *testing.T) {
	f := fakeStore(t)
	h := t.TempDir()
	config(t, h, "auto")
	f.item = auth("old")
	file(t, h, auth("stale"))
	_, loc, err := Read(h)
	if err != nil {
		t.Fatal(err)
	}
	if err := loc.Write(auth("rotated")); err != nil {
		t.Fatal(err)
	}
	var got, want any
	json.Unmarshal(f.item, &got)
	json.Unmarshal(auth("rotated"), &want)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("rotated tokens or unknown fields were lost")
	}
	if _, err := os.Stat(filepath.Join(h, "auth.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("secure rotation left a file credential behind")
	}
	for _, call := range f.calls {
		value := func(flag string) string {
			for i := 1; i+1 < len(call); i++ {
				if call[i] == flag {
					return call[i+1]
				}
			}
			return ""
		}
		if value("-s") != service || value("-a") != keychainAccount(h) {
			t.Fatal("wrong Keychain service/account selected")
		}
	}
}
func TestSwitchAndDeleteUseKeychain(t *testing.T) {
	f := fakeStore(t)
	h := t.TempDir()
	config(t, h, "keyring")
	f.item = auth("old")
	if err := Save(h, auth("switched")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(f.item, []byte("switched")) {
		t.Fatal("switch did not update secure credentials")
	}
	if err := Delete(h); err != nil {
		t.Fatal(err)
	}
	if f.item != nil {
		t.Fatal("logout left Keychain login active")
	}
	if ChatGPT(h) {
		t.Fatal("logged-out secure account still detected")
	}
}
func TestAutoSaveFallback(t *testing.T) {
	f := fakeStore(t)
	h := t.TempDir()
	config(t, h, "auto")
	f.refuseWrite = true
	if err := Save(h, auth("fallback")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(h, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatal("file fallback is not private")
	}
}
func TestDiscoveryOffReadsAndWritesNothing(t *testing.T) {
	f := fakeStore(t)
	h := t.TempDir()
	config(t, h, "keyring")
	f.item = auth("unchanged")
	t.Setenv("MAGPIE_NO_ACCOUNTS", "1")
	if _, _, err := Read(h); err == nil {
		t.Fatal("discovery off read credentials")
	}
	if err := Save(h, auth("new")); err == nil {
		t.Fatal("discovery off wrote credentials")
	}
	if err := Delete(h); err == nil {
		t.Fatal("discovery off removed credentials")
	}
	if len(f.calls) != 0 {
		t.Fatal("discovery off ran security")
	}
}
func TestInvalidAndEphemeralStoresDoNotProbe(t *testing.T) {
	for _, m := range []string{"ephemeral", "unknown"} {
		t.Run(m, func(t *testing.T) {
			f := fakeStore(t)
			h := t.TempDir()
			config(t, h, m)
			file(t, h, auth("stale"))
			if ChatGPT(h) {
				t.Fatal("unshared/invalid store used stale file")
			}
			if err := Save(h, auth("new")); err == nil {
				t.Fatal("invalid store accepted a write")
			}
			if len(f.calls) != 0 {
				t.Fatal("unshared store probed Keychain")
			}
		})
	}
}
func TestCanonicalHomeKey(t *testing.T) {
	h := t.TempDir()
	link := filepath.Join(t.TempDir(), "codex-home")
	if err := os.Symlink(h, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if keychainAccount(h) != keychainAccount(link) {
		t.Fatal("symlink changed the Codex key")
	}
	if keychainAccount(h) == keychainAccount(t.TempDir()) {
		t.Fatal("two CODEX_HOMEs share a secure account")
	}
	if got := keychainAccount("/a/nonexistent/codex-home-reference"); got != "cli|01b70d519e639d6a" {
		t.Fatalf("Codex SHA-256 contract mismatch: %s", got)
	}
}

func TestSecureSaveCleanupFailureDoesNotFallBack(t *testing.T) {
	f := fakeStore(t)
	h := t.TempDir()
	config(t, h, "auto")
	f.item = auth("old")
	path := filepath.Join(h, "auth.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "held"), []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Save(h, auth("new")); err == nil {
		t.Fatal("cleanup failure reported as a complete save")
	}
	if !bytes.Contains(f.item, []byte("new")) {
		t.Fatal("secure save did not precede file cleanup")
	}
	if _, err := os.Stat(filepath.Join(path, "held")); err != nil {
		t.Fatal("cleanup failure overwrote the fallback")
	}
}

func TestUnreadableConfigDoesNotReadOrOverwriteCredentials(t *testing.T) {
	f := fakeStore(t)
	h := t.TempDir()
	file(t, h, auth("unchanged"))
	if err := os.WriteFile(filepath.Join(h, "config.toml"), []byte("cli_auth_credentials_store = ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(h); err == nil {
		t.Fatal("invalid configuration was treated as default file storage")
	}
	if err := Save(h, auth("new")); err == nil {
		t.Fatal("invalid configuration allowed a credential write")
	}
	if len(f.calls) != 0 {
		t.Fatal("invalid configuration probed Keychain")
	}
	if b, _ := os.ReadFile(filepath.Join(h, "auth.json")); !bytes.Equal(b, auth("unchanged")) {
		t.Fatal("invalid configuration overwrote credentials")
	}
}
