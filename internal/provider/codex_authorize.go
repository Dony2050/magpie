package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/proc"
)

// AuthorizeCodexKeychain lets the installed, signed Codex read its own
// sign-in (#2367). macOS owns the prompt and the password; a successful
// one-time Allow is not mistaken for persistent partition authorization.
// user is the account the caller just selected, so a stale page cannot
// report authorization for an account since switched away from.
func AuthorizeCodexKeychain(ctx context.Context, user string) error {
	if !codexAuthorizing.TryLock() {
		return errors.New("Codex authorization is already waiting for an answer")
	}
	defer codexAuthorizing.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	home := codexHome()
	b, store, err := readCodexLogin(home, false)
	if err != nil || !store.keychain {
		return errors.New("Codex is not signed in through the macOS keychain")
	}
	var auth codexAuth
	if json.Unmarshal(b, &auth) != nil {
		return errors.New("Codex's account changed; authorize the current account instead")
	}
	currentUser := codexLiveName(codexUser(jwtClaims(auth.Tokens.IDToken)), bytes.TrimSpace(b))
	if user == "" || !strings.EqualFold(currentUser, user) {
		return errors.New("Codex's account changed; authorize the current account instead")
	}
	exe, partition, err := codexAuthorizationTool(ctx)
	if err != nil {
		return err
	}
	if err := codexAuthorizationRead(ctx, exe, home); err != nil {
		if ctx.Err() != nil {
			return errors.New("Codex authorization was cancelled or timed out; the account is still switched")
		}
		return errors.New("Codex could not read the sign-in; retry and choose Always Allow in the macOS prompt")
	}
	partitions, err := codexAuthorizationPartitions(ctx, home)
	if err != nil {
		return errors.New("Codex read the sign-in, but its saved keychain permission could not be checked; retry authorization")
	}
	if !slices.Contains(partitions, partition) {
		return errors.New("Codex's keychain permission was not saved; retry and choose Always Allow instead of Allow")
	}
	if err := codexAuthorizationRead(ctx, exe, home); err != nil {
		return errors.New("Codex could not read the sign-in again after authorization; retry authorization")
	}
	// Check the account again after the prompt: waiting holds no credential
	// lock, and the user or a background refresh can change the sign-in.
	after, current, err := readCodexLogin(home, true)
	if err != nil || !current.keychain || string(after) != string(b) {
		return errors.New("Codex's sign-in changed during authorization; authorize the current account again")
	}
	return nil
}

var (
	codexAuthorizing             sync.Mutex
	codexAuthorizationTool       = findCodexAuthorizationTool
	codexAuthorizationRead       = readWithCodex
	codexAuthorizationPartitions = readCodexPartitions
)

// The desktop app's CLI is preferred: an unsigned npm CLI has a different
// partition and cannot authorize the desktop app. Find the current install
// each time, including renamed/moved bundles Spotlight knows about.
func findCodexAuthorizationTool(ctx context.Context) (string, string, error) {
	if runtime.GOOS != "darwin" {
		return "", "", errors.New("Codex keychain authorization is available only on macOS")
	}
	var candidates []string
	if !proc.Isolated() {
		if ps, err := listProcesses(ctx); err == nil {
			for _, p := range ps {
				exe, _ := splitExe(p.Args)
				if strings.Contains(exe, ".app/Contents/") && filepath.Base(exe) == "codex" {
					candidates = append(candidates, exe)
				}
			}
		}
	}
	dirs := proc.SystemDirs("/Applications")
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	var bundles []string
	for _, dir := range dirs {
		for _, name := range []string{"ChatGPT.app", "Codex.app"} {
			bundles = append(bundles, filepath.Join(dir, name))
		}
	}
	if !proc.Isolated() {
		out, _ := proc.CommandContext(ctx, "/usr/bin/mdfind", "kMDItemCFBundleIdentifier == 'com.openai.codex'").Output()
		bundles = append(bundles, strings.Split(strings.TrimSpace(string(out)), "\n")...)
	}
	for _, bundle := range bundles {
		if bundle == "" {
			continue
		}
		for _, rel := range []string{"Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex", "Contents/Resources/codex"} {
			candidates = append(candidates, filepath.Join(bundle, rel))
		}
	}
	if path := proc.FindTool("codex"); path != "" {
		candidates = append(candidates, path)
	}
	for _, exe := range candidates {
		if st, err := os.Stat(exe); err != nil || st.IsDir() {
			continue
		}
		if partition, err := codexSigningPartition(ctx, exe); err == nil {
			return exe, partition, nil
		}
	}
	return "", "", errors.New("the signed official Codex could not be found; open Codex manually and choose Always Allow")
}

// Validate the publisher certificate, then derive this install's partition
// rather than pinning a version, executable hash or team identifier.
func codexSigningPartition(ctx context.Context, exe string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	requirement := `anchor apple generic and certificate leaf[subject.O] = "OpenAI OpCo, LLC"`
	if err := proc.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "-R="+requirement, exe).Run(); err != nil {
		return "", errors.New("Codex's OpenAI signature could not be verified")
	}
	out, err := proc.CommandContext(ctx, "/usr/bin/codesign", "-d", "--verbose=4", exe).CombinedOutput()
	if err != nil {
		return "", errors.New("Codex's signing identity could not be read")
	}
	for _, line := range strings.Split(string(out), "\n") {
		if team, ok := strings.CutPrefix(line, "TeamIdentifier="); ok && team != "" && team != "not set" {
			return "teamid:" + team, nil
		}
	}
	return "", errors.New("Codex has no signing team identifier")
}

func readWithCodex(ctx context.Context, exe, home string) error {
	cmd := proc.CommandContext(ctx, exe, "login", "status")
	cmd.Dir = home
	// Auth environment overrides can bypass the keychain altogether. Keep
	// HOME (the login keychain's home), but use the exact switched CODEX_HOME.
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(key, "CODEX_") && !strings.HasPrefix(key, "OPENAI_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "CODEX_HOME="+home)
	// Output is intentionally discarded: vendor errors can include private
	// config or credential details. The caller reports the operation only.
	return cmd.Run()
}

// Security.framework can retain an old access object in a long-lived
// process. Inspect metadata in a fresh copy of this binary, requesting
// neither the password nor an interactive authorization of its own.
func readCodexPartitions(ctx context.Context, home string) ([]string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := proc.CommandContext(ctx, exe, "accounts", "keychain-metadata", home).Output()
	if err != nil {
		return nil, fmt.Errorf("keychain metadata helper failed: %w", err)
	}
	var partitions []string
	if err := json.Unmarshal(out, &partitions); err != nil || partitions == nil {
		return nil, errors.New("keychain partition metadata could not be read")
	}
	return partitions, nil
}
