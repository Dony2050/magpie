//go:build !windows

package provider

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/testenv"
)

func TestCodexAuthorizationReadsTheSwitchedHome(t *testing.T) {
	home := t.TempDir()
	exe := filepath.Join(t.TempDir(), "codex")
	record := filepath.Join(home, "read")
	testenv.Program(t, exe, "#!/bin/sh\nprintf '%s|%s|%s|%s|%s' \"$*\" \"$CODEX_HOME\" \"$OPENAI_API_KEY\" \"$CODEX_ACCESS_TOKEN\" \"$PWD\" > '"+record+"'\n")
	t.Setenv("OPENAI_API_KEY", "not-a-real-key")
	t.Setenv("CODEX_ACCESS_TOKEN", "not-a-real-token")
	t.Setenv("CODEX_HOME", "/previous/home")
	if err := readWithCodex(context.Background(), exe, home); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(record)
	resolved, _ := filepath.EvalSymlinks(home)
	want := "login status|" + home + "|||" + resolved
	if err != nil || string(b) != want {
		t.Fatalf("read: %q, %v; want %q", b, err, want)
	}
}

func TestCodexAuthorizationRejectsUnsignedTool(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS code signature")
	}
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	testenv.Program(t, filepath.Join(bin, "codex"), "#!/bin/sh\nexit 0\n")
	if path, _, err := findCodexAuthorizationTool(context.Background()); err == nil || path != "" {
		t.Fatalf("unsigned CLI was trusted: %q, %v", path, err)
	}
	if _, err := codexSigningPartition(context.Background(), filepath.Join(bin, "codex")); err == nil || strings.Contains(err.Error(), bin) {
		t.Fatalf("signature error: %v", err)
	}
}
