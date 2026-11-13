//go:build windows

package mpengine

import (
	"os"
	"syscall"
)

const (
	fileFlagBackupSemantics = 0x02000000
)

// openShared opens path for reading without blocking Defender, which keeps
// the database open for writing.
func openShared(path string) (*os.File, error) {
	path16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(
		path16,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		fileFlagBackupSemantics,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}
