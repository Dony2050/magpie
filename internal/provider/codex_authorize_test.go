package provider

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexAuthorizationDistinguishesWorkspaceSeats(t *testing.T) {
	k, account, reads := codexAuthorizationRig(t)
	home := filepath.Dir(codexHome())
	var seats []savedLogin
	for _, workspace := range []string{"ws-one", "ws-two"} {
		codexWorkspaceSignIn(t, home, "me@example.com", workspace, "refresh-"+workspace)
		auth, err := os.ReadFile(filepath.Join(codexHome(), "auth.json"))
		if err != nil {
			t.Fatal(err)
		}
		seats = append(seats, savedLogin{Agent: "codex", User: "me@example.com · Team", Auth: auth})
	}
	seats = nameAlike(seats)
	if err := writeLogins(seats); err != nil {
		t.Fatal(err)
	}
	k.set(account, seats[1].Auth)
	resetCodexKeychain()
	if err := AuthorizeCodexKeychain(context.Background(), seats[0].User); err == nil || *reads != 0 {
		t.Fatalf("the other workspace started authorization: %v, reads=%d", err, *reads)
	}
	if err := AuthorizeCodexKeychain(context.Background(), seats[1].User); err != nil {
		t.Fatalf("the selected workspace could not authorize: %v", err)
	}
	if *reads != 2 {
		t.Fatalf("the selected workspace had %d reads, want 2", *reads)
	}
}

func codexAuthorizationRig(t *testing.T) (*fakeKeychain, string, *int) {
	t.Helper()
	home := signIn(t)
	k, account := codexInKeychain(t, home, "keyring")
	tool, read, partitions := codexAuthorizationTool, codexAuthorizationRead, codexAuthorizationPartitions
	t.Cleanup(func() {
		codexAuthorizationTool, codexAuthorizationRead, codexAuthorizationPartitions = tool, read, partitions
	})
	codexAuthorizationTool = func(context.Context) (string, string, error) { return "official-codex", "teamid:current", nil }
	reads := new(int)
	codexAuthorizationRead = func(_ context.Context, exe, dir string) error {
		if exe != "official-codex" || dir != filepath.Join(home, ".codex") {
			t.Errorf("authorization used %q in %q", exe, dir)
		}
		*reads++
		return nil
	}
	codexAuthorizationPartitions = func(context.Context, string) ([]string, error) {
		return []string{"apple-tool:", "teamid:current"}, nil
	}
	return k, account, reads
}

// A successful CLI read alone must not claim persistent authorization.
// The saved partition is derived from this install, not a pinned Team ID.
func TestCodexAuthorizationNeedsSavedPermission(t *testing.T) {
	for _, tc := range []struct {
		name       string
		partitions []string
		err        error
		want       string
	}{
		{"Always Allow", []string{"apple-tool:", "teamid:current"}, nil, ""},
		{"Allow only", []string{"apple-tool:"}, nil, "not saved"},
		{"a different signer", []string{"teamid:previous"}, nil, "not saved"},
		{"metadata unreadable", nil, errors.New("private details"), "could not be checked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, reads := codexAuthorizationRig(t)
			codexAuthorizationPartitions = func(context.Context, string) ([]string, error) { return tc.partitions, tc.err }
			err := AuthorizeCodexKeychain(context.Background(), "me@example.com")
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("authorization: %v, want %q", err, tc.want)
			}
			want := 1
			if tc.want == "" {
				want = 2 // a fresh Codex process reads without a second prompt
			}
			if *reads != want {
				t.Fatalf("%d Codex reads, want %d", *reads, want)
			}
		})
	}
}

func TestCodexAuthorizationKeepsFailureSeparate(t *testing.T) {
	for _, tc := range []string{"refused", "cancelled", "missing tool", "account changed", "changed while waiting", "file"} {
		t.Run(tc, func(t *testing.T) {
			k, account, reads := codexAuthorizationRig(t)
			before := string(k.item(account))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			user := "me@example.com"
			switch tc {
			case "refused":
				codexAuthorizationRead = func(context.Context, string, string) error { return errors.New("SECRET-DO-NOT-SHOW") }
			case "cancelled":
				cancel()
				codexAuthorizationRead = func(ctx context.Context, _, _ string) error { return ctx.Err() }
			case "missing tool":
				codexAuthorizationTool = func(context.Context) (string, string, error) { return "", "", errors.New("not installed") }
			case "account changed":
				user = "previous@example.com"
			case "changed while waiting":
				codexAuthorizationRead = func(context.Context, string, string) error {
					keepCodexKeychain(codexHome(), append([]byte(before), ' '))
					return nil
				}
			case "file":
				// No keychain item: auto's file fallback cannot authorize
				// Codex's keychain, even when another item exists elsewhere.
				k.findErr = errors.New("not available")
				resetCodexKeychain()
			}
			if err := AuthorizeCodexKeychain(ctx, user); err == nil || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("%s: %v", tc, err)
			}
			if string(k.item(account)) != before {
				t.Fatal("authorization failure rewrote or rolled back the switched credential")
			}
			if tc == "account changed" && *reads != 0 {
				t.Fatal("a stale request launched Codex")
			}
		})
	}
}

func TestCodexAuthorizationDoesNotStackPrompts(t *testing.T) {
	_, _, _ = codexAuthorizationRig(t)
	started := make(chan struct{})
	codexAuthorizationRead = func(ctx context.Context, _, _ string) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- AuthorizeCodexKeychain(ctx, "me@example.com") }()
	<-started
	err := AuthorizeCodexKeychain(context.Background(), "me@example.com")
	cancel()
	first := <-done
	if err == nil || !strings.Contains(err.Error(), "already waiting") || first == nil {
		t.Fatalf("overlap: %v; cancelled original: %v", err, first)
	}
	// The cancellation released its slot; retry can finish normally.
	codexAuthorizationRead = func(context.Context, string, string) error { return nil }
	if err := AuthorizeCodexKeychain(context.Background(), "me@example.com"); err != nil {
		t.Fatal(err)
	}
}
