//go:build windows

package mpengine

import (
	"io"
	"os"
	"syscall"
)

const (
	fileFlagBackupSemantics = 0x02000000
)

func readFile(path string) ([]byte, error) {
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
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	return io.ReadAll(f)
}
