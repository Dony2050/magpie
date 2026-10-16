//go:build !darwin || !cgo

package provider

import "errors"

func CodexKeychainPartitions(string) ([]string, error) {
	return nil, errors.New("checking Codex keychain permissions requires a macOS build with native keychain support")
}
