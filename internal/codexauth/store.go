// Package codexauth reads and updates the login Codex itself uses. On macOS
// its configured store can be a file, the Keychain, or Keychain with a file
// fallback. A rotation is written back to the store it was read from.
package codexauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/yetone/magpie/internal/edit"
	"github.com/yetone/magpie/internal/filememo"
	"github.com/yetone/magpie/internal/proc"
	"github.com/yetone/magpie/internal/settings"
	"github.com/yetone/magpie/internal/steady"
)

const service = "Codex Auth"

var keychainSupported = runtime.GOOS == "darwin"
var runSecurity = security
var errKeychainWrite = errors.New("cannot save Codex credentials in macOS Keychain")
var errDiscoveryOff = errors.New("Codex credential discovery is off")

// Location identifies the selected credential store without holding a token.
// Callers keep it with a read and use it for the corresponding rotation.
type Location struct {
	home     string
	keychain bool
}

func mode(home string) (string, error) {
	m, err := filememo.Read("codex credential store", filepath.Join(home, "config.toml"), func(b []byte) (string, error) {
		var c struct {
			Store string `toml:"cli_auth_credentials_store"`
		}
		if err := toml.Unmarshal(b, &c); err != nil {
			return "", errors.New("cannot parse Codex credential store setting")
		}
		return c.Store, nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if m == "" {
		m = "file"
	}
	switch m {
	case "file", "keyring", "auto", "ephemeral":
		return m, nil
	}
	return "", errors.New("unknown Codex credential store setting")
}

// keychainAccount follows Codex 0.162.1's compute_store_key: canonicalize
// CODEX_HOME when possible, then take the first 16 SHA-256 hex characters.
func keychainAccount(home string) string {
	if canonical, err := filepath.EvalSymlinks(home); err == nil {
		home = canonical
	}
	sum := sha256.Sum256([]byte(home))
	return "cli|" + hex.EncodeToString(sum[:])[:16]
}

// Read honors the storage setting under home. auto prefers the Keychain,
// falling back to auth.json when the item is absent or cannot be read, as
// Codex does. keyring never falls back; file never probes the Keychain.
func Read(home string) ([]byte, Location, error) {
	loc := Location{home: home}
	if settings.AccountDiscoveryOff() {
		return nil, loc, errDiscoveryOff
	}
	m, err := mode(home)
	if err != nil {
		return nil, loc, err
	}
	if m == "ephemeral" {
		return nil, loc, fs.ErrNotExist
	}
	if m == "keyring" || m == "auto" {
		loc.keychain = true
		b, err := readKeychain(home)
		if err == nil || m == "keyring" {
			return b, loc, err
		}
		loc.keychain = false
	}
	b, err := steady.ReadThere(filepath.Join(home, "auth.json"))
	return b, loc, err
}

// Save places a new or switched login where Codex will read it. A failed
// read of an existing keyring item is not treated as an absent item and
// never authorizes replacing it. auto may create a file if secure storage
// is unavailable, matching Codex's own fallback.
func Save(home string, b []byte) error {
	if settings.AccountDiscoveryOff() {
		return errDiscoveryOff
	}
	m, err := mode(home)
	if err != nil {
		return err
	}
	if m == "ephemeral" {
		return errors.New("Codex uses ephemeral credentials; sign in from Codex instead")
	}
	loc := Location{home: home}
	if m == "keyring" || m == "auto" {
		if !keychainSupported && m == "auto" {
			return loc.Write(b)
		}
		_, err := readKeychain(home)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		loc.keychain = true
		if err := loc.Write(b); !errors.Is(err, errKeychainWrite) || m == "keyring" {
			return err
		}
		// Never leave a different file beside a successfully updated keyring.
		// Write only falls back when the secure write itself was refused.
		loc.keychain = false
	}
	return loc.Write(b)
}

// Write preserves all JSON fields and updates this exact source. Secure
// writes never create auth.json as a second holder of a rotating token.
func (loc Location) Write(b []byte) error {
	if settings.AccountDiscoveryOff() {
		return errDiscoveryOff
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, b); err != nil {
		return errors.New("unreadable Codex credentials")
	}
	defer filememo.Forget()
	if loc.keychain {
		if !keychainSupported {
			return errors.New("Codex Keychain storage is unavailable on this platform")
		}
		// -w is the same platform tool used for Claude Code. Never include its
		// output or argv in an error: either can contain the credential.
		_, err := runSecurity("add-generic-password", "-U", "-s", service, "-a", keychainAccount(loc.home), "-w", compact.String())
		if err != nil {
			return errKeychainWrite
		}
		// Codex removes its file fallback after a successful secure save.
		if err := os.Remove(filepath.Join(loc.home, "auth.json")); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return errors.New("Codex Keychain saved, but the file fallback could not be removed")
		}
		return nil
	}
	path, err := edit.Target(filepath.Join(loc.home, "auth.json"))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return steady.WriteFile(path, append(bytes.TrimSpace(b), '\n'), 0o600)
}

// Delete signs out the selected store, including its file fallback. Other
// CODEX_HOMEs' keychain entries are never selected by service alone.
func Delete(home string) error {
	if settings.AccountDiscoveryOff() {
		return errDiscoveryOff
	}
	m, err := mode(home)
	if err != nil {
		return err
	}
	if m == "ephemeral" {
		return errors.New("Codex uses ephemeral credentials; sign out from Codex instead")
	}
	if m == "keyring" || m == "auto" {
		if !keychainSupported {
			if m == "keyring" {
				return errors.New("Codex Keychain storage is unavailable on this platform")
			}
		} else {
			_, err := runSecurity("delete-generic-password", "-s", service, "-a", keychainAccount(home))
			if err != nil && !missingItem(err) {
				return errors.New("cannot remove Codex credentials from macOS Keychain")
			}
		}
	}
	defer filememo.Forget()
	err = os.Remove(filepath.Join(home, "auth.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func readKeychain(home string) ([]byte, error) {
	if !keychainSupported {
		return nil, errors.New("Codex Keychain storage is unavailable on this platform")
	}
	b, err := runSecurity("find-generic-password", "-s", service, "-a", keychainAccount(home), "-w")
	if err != nil {
		if missingItem(err) {
			return nil, fs.ErrNotExist
		}
		return nil, errors.New("cannot read Codex credentials from macOS Keychain")
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] != '{' {
		if decoded, err := hex.DecodeString(string(b)); err == nil {
			b = decoded
		}
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(b, &obj) != nil || obj == nil {
		return nil, errors.New("unreadable Codex Keychain credentials")
	}
	return b, nil
}

func security(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return proc.CommandContext(ctx, "security", args...).Output()
}

func missingItem(err error) bool {
	var exit *exec.ExitError
	return errors.Is(err, fs.ErrNotExist) || errors.As(err, &exit) && exit.ExitCode() == 44 // errSecItemNotFound (-25300)
}

// Description names the sources checked, without credentials or vendor output.
func Description(home string) string {
	m, err := mode(home)
	if err != nil {
		return "unreadable Codex credential store setting"
	}
	path := filepath.Join(home, "auth.json")
	switch m {
	case "keyring":
		return "macOS Keychain (Codex Auth for this CODEX_HOME)"
	case "auto":
		return fmt.Sprintf("macOS Keychain (Codex Auth for this CODEX_HOME), then %s", path)
	case "ephemeral":
		return "Codex's in-memory credentials (not shared with magpie)"
	}
	return "nothing at " + path
}

// ChatGPT reports a subscription login, rather than an API key, from any
// supported store. Agent wiring uses the same reader as provider discovery.
func ChatGPT(home string) bool {
	b, _, err := Read(home)
	if err != nil {
		return false
	}
	var a struct {
		Mode   string `json:"auth_mode"`
		Tokens struct {
			Access string `json:"access_token"`
		} `json:"tokens"`
	}
	return json.Unmarshal(b, &a) == nil && a.Mode != "apikey" && strings.TrimSpace(a.Tokens.Access) != ""
}
