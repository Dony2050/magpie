//go:build darwin && cgo

package provider

/*
#cgo LDFLAGS: -framework Foundation -framework Security
#include <stdlib.h>
char *magpieCodexPartitions(const char *service, const char *account, int *status);
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/yetone/magpie/internal/proc"
)

// CodexKeychainPartitions is used only by the metadata helper process.
// The native reader disables interaction in that process and never asks
// for the item's password. Normal tests must stand in the reader.
func CodexKeychainPartitions(home string) ([]string, error) {
	if proc.Isolated() {
		return nil, fmt.Errorf("tests do not read the machine's keychain")
	}
	s, a := C.CString(codexKeychainService), C.CString(codexKeychainAccount(home))
	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(a))
	var status C.int
	raw := C.magpieCodexPartitions(s, a, &status)
	if raw == nil {
		return nil, fmt.Errorf("keychain partition metadata unavailable (%d)", int(status))
	}
	defer C.free(unsafe.Pointer(raw))
	var partitions []string
	if err := json.Unmarshal([]byte(C.GoString(raw)), &partitions); err != nil {
		return nil, err
	}
	return partitions, nil
}
