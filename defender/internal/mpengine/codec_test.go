package mpengine_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/rakeshrm/osquery-defender-extension/internal/mpengine"
)

func TestCodecRoundTrip(t *testing.T) {
	key := mpengine.KnownKeys["1.1.26100.4"]
	ps := 4096
	ks, err := mpengine.RC4Stream(key, ps)
	if err != nil {
		t.Fatalf("RC4Stream failed: %v", err)
	}

	// Test Page 1:
	// bytes 0..15 XOR, 16..23 clear, 24.. XOR with keystream restart
	page1 := make([]byte, ps)
	if _, err := rand.Read(page1); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	copy(page1[:16], mpengine.Magic)

	encPage1 := mpengine.EncryptPage(page1, 1, ks)
	// Verify bytes 16..24 were not changed
	if !bytes.Equal(encPage1[16:24], page1[16:24]) {
		t.Errorf("page 1 bytes 16..23 were modified during encryption")
	}
	decPage1 := mpengine.DecryptPage(encPage1, 1, ks)
	if !bytes.Equal(decPage1, page1) {
		t.Fatalf("page 1 roundtrip failed")
	}

	// Test Page 2..5 (non-page-1):
	for pgno := 2; pgno <= 5; pgno++ {
		pageN := make([]byte, ps)
		if _, err := rand.Read(pageN); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}
		encPageN := mpengine.EncryptPage(pageN, pgno, ks)
		decPageN := mpengine.DecryptPage(encPageN, pgno, ks)
		if !bytes.Equal(decPageN, pageN) {
			t.Fatalf("page %d roundtrip failed", pgno)
		}
	}
}
