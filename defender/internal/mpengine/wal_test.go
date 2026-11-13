package mpengine_test

import (
	"encoding/binary"
	"testing"

	"github.com/huntbase-io/osquery-defender/internal/mpengine"
)

func TestWalCksum(t *testing.T) {
	// Little endian checksum
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], 0x12345678)
	binary.LittleEndian.PutUint32(data[4:8], 0x0abcdef0)
	binary.LittleEndian.PutUint32(data[8:12], 0x11111111)
	binary.LittleEndian.PutUint32(data[12:16], 0x22222222)

	s0, s1 := mpengine.WalCksum(data, 0, 0, false)
	if s0 == 0 && s1 == 0 {
		t.Errorf("expected non-zero checksum")
	}

	// Big endian checksum
	bdata := make([]byte, 16)
	binary.BigEndian.PutUint32(bdata[0:4], 0x12345678)
	binary.BigEndian.PutUint32(bdata[4:8], 0x0abcdef0)
	binary.BigEndian.PutUint32(bdata[8:12], 0x11111111)
	binary.BigEndian.PutUint32(bdata[12:16], 0x22222222)

	bs0, bs1 := mpengine.WalCksum(bdata, 0, 0, true)
	if bs0 == 0 && bs1 == 0 {
		t.Errorf("expected non-zero checksum")
	}
}
