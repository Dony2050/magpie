package provider

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// A refusal is a choice, not a timer. Neither polling, a fresh token
// read nor account-cache invalidation may ask again; only Try again may.
func TestCodexKeychainPausedUntilRetry(t *testing.T) {
	for _, failure := range []error{errKeychainRefused, errKeychainNoAnswer, errKeychainUnread} {
		t.Run(failure.Error(), func(t *testing.T) {
			home := signIn(t)
			dir := filepath.Join(home, ".codex")
			t.Setenv("CODEX_HOME", dir)
			k, account := codexInKeychain(t, home, "keyring")
			k.findErr = failure
			if _, err := findCodexKeychain(dir, false); !errors.Is(err, failure) {
				t.Fatalf("first read: %v", err)
			}
			k.findErr = nil
			for range 3 {
				ageCodexKeychain(account, 24*time.Hour)
				ForgetAccounts()
				for _, fresh := range []bool{false, true} {
					if _, err := findCodexKeychain(dir, fresh); !errors.Is(err, failure) {
						t.Fatalf("paused read, fresh=%v: %v", fresh, err)
					}
				}
			}
			if finds, _ := k.counts(); finds != 1 {
				t.Fatalf("%d prompts before explicit retry, want 1", finds)
			}
			if err := RetryCodexKeychain(); err != nil {
				t.Fatalf("explicit retry: %v", err)
			}
			if finds, _ := k.counts(); finds != 2 {
				t.Fatalf("%d prompts after explicit retry, want 2", finds)
			}
			if _, _, err := readCodexLogin(dir, false); err != nil {
				t.Fatalf("retry did not restore the sign-in: %v", err)
			}
		})
	}
}

func TestCodexKeychainLateWriteKeepsPause(t *testing.T) {
	home := signIn(t)
	dir := filepath.Join(home, ".codex")
	k, account := codexInKeychain(t, home, "keyring")
	k.findErr = errKeychainRefused
	if _, err := findCodexKeychain(dir, false); !errors.Is(err, errKeychainRefused) {
		t.Fatalf("first read: %v", err)
	}
	// A refresh started before the refusal can finish afterwards. Saving
	// its token is not permission to lift the refusal.
	keepCodexKeychain(dir, k.item(account))
	if _, err := findCodexKeychain(dir, false); !errors.Is(err, errKeychainRefused) {
		t.Fatalf("a late write lifted the pause: %v", err)
	}
}

func TestCodexKeychainRetryKeepsOtherHomesPaused(t *testing.T) {
	home := signIn(t)
	dir := filepath.Join(home, ".codex")
	t.Setenv("CODEX_HOME", dir)
	k, _ := codexInKeychain(t, home, "keyring")
	other := filepath.Join(home, "other-codex")
	k.set(codexKeychainAccount(other), []byte(`{"tokens":{}}`))
	k.findErr = errKeychainRefused
	for _, d := range []string{dir, other} {
		if _, err := findCodexKeychain(d, false); !errors.Is(err, errKeychainRefused) {
			t.Fatalf("first read of %s: %v", d, err)
		}
	}
	k.findErr = nil
	if err := RetryCodexKeychain(); err != nil {
		t.Fatal(err)
	}
	if _, err := findCodexKeychain(other, true); !errors.Is(err, errKeychainRefused) {
		t.Fatalf("another home's refusal was lifted: %v", err)
	}
	if finds, _ := k.counts(); finds != 3 {
		t.Fatalf("%d prompts, want the two initial reads and one retry", finds)
	}
}

func TestCodexKeychainRetryOffKeepsPause(t *testing.T) {
	home := signIn(t)
	dir := filepath.Join(home, ".codex")
	t.Setenv("CODEX_HOME", dir)
	k, _ := codexInKeychain(t, home, "keyring")
	k.findErr = errKeychainRefused
	findCodexKeychain(dir, false)
	t.Setenv("MAGPIE_NO_ACCOUNTS", "1")
	if err := RetryCodexKeychain(); !errors.Is(err, errAccountDiscoveryOff) {
		t.Fatalf("retry with discovery off: %v", err)
	}
	t.Setenv("MAGPIE_NO_ACCOUNTS", "")
	k.findErr = nil
	if _, err := findCodexKeychain(dir, true); !errors.Is(err, errKeychainRefused) {
		t.Fatalf("disabled retry lifted the pause: %v", err)
	}
	if finds, _ := k.counts(); finds != 1 {
		t.Fatalf("%d prompts after a disabled retry, want 1", finds)
	}
}

func TestCodexKeychainWaitingOfferedAsPending(t *testing.T) {
	home := signIn(t)
	rememberLogins(true)
	dir := filepath.Join(home, ".codex")
	t.Setenv("CODEX_HOME", dir)
	k, account := codexInKeychain(t, home, "keyring")
	defer func(old time.Duration) { keychainHold = old }(keychainHold)
	keychainHold = time.Millisecond
	gate := make(chan struct{})
	k.gate = gate
	if _, err := findCodexKeychain(dir, false); !errors.Is(err, errKeychainWaiting) {
		close(gate)
		t.Fatalf("a pending read: %v", err)
	}
	codexKeychainMu.Lock()
	ask := codexKeychainAsks[account]
	codexKeychainMu.Unlock()
	defer func() { close(gate); <-ask.done }()
	if x := codexExclusion(t); x == nil || !x.Retry || !x.KeychainWaiting {
		t.Fatalf("waiting isn't exposed to the Providers notice: %+v", x)
	}
}

func TestCodexKeychainInvalidItemCanRetry(t *testing.T) {
	home := signIn(t)
	rememberLogins(true)
	dir := filepath.Join(home, ".codex")
	t.Setenv("CODEX_HOME", dir)
	k, account := codexInKeychain(t, home, "keyring")
	valid := k.item(account)
	k.set(account, []byte("not JSON"))
	if _, err := findCodexKeychain(dir, false); err == nil {
		t.Fatal("an invalid item was read as a sign-in")
	}
	if x := codexExclusion(t); x == nil || !x.Retry || x.KeychainWaiting {
		t.Fatalf("an unreadable item offers no retry: %+v", x)
	}
	k.set(account, valid)
	if err := RetryCodexKeychain(); err != nil {
		t.Fatalf("retry after the item was repaired: %v", err)
	}
}
