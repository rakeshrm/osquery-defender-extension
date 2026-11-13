//go:build !windows

package mpengine

import "os"

func openShared(path string) (*os.File, error) {
	return os.Open(path)
}
