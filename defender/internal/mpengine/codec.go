package mpengine

import (
	"crypto/rc4"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Magic is the standard SQLite 3 header string.
var Magic = []byte("SQLite format 3\x00")

// KnownKeys maps engine build strings to known 256-byte RC4 keys found in mpengine.dll.
var KnownKeys = map[string][]byte{
	"1.1.26100.4": hexDecode(
		"1e87781b8dbaa844ce69702c0c78b786a3f623b738f5edf9af83530fb3fc54fa" +
			"a21eb9cf1331fd0f0da954f687cb9e18279697900e53fb317c9cbce48e23d053" +
			"71ecc15951b8f3649d7ca33ed68dc9047e82c9baad9799d0d458cb847ca9ffbe" +
			"3c8a775233557dde13a8b14087cc1bc8f10f6ecdd083a959cff84a9d1d50755e" +
			"3e191818af23e2293558766d2c07e25712b2ca0b535ed8f6c56ce73d24bdd029" +
			"1771861a54b4c285a9a3db7aca6d224aeacd621db9f2a22ed1e9e11d75bed7dc" +
			"0ecb0a8e68a2ff1263408dc808dffd164b116774cd0b9b8d05411ed6262e429b" +
			"a495676b8398db2f35d3c1b9ced52636f2765e1a95cb7ca4c3ddabddbff38253",
	),
}

func hexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// RC4Stream generates n bytes of RC4 keystream for key.
func RC4Stream(key []byte, n int) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("empty rc4 key")
	}
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	c.XORKeyStream(out, out)
	return out, nil
}

// Codec handles RC4 page decryption and encryption for MetaVault SQLite databases.
type Codec struct {
	keystream []byte
	pageSize  int
}

// NewCodec creates a new Codec for the given keystream and page size.
func NewCodec(keystream []byte, pageSize int) *Codec {
	return &Codec{
		keystream: keystream,
		pageSize:  pageSize,
	}
}

// DecryptPage decrypts page data with the given pgno (1-based).
func (c *Codec) DecryptPage(data []byte, pgno int) []byte {
	return DecryptPage(data, pgno, c.keystream)
}

// EncryptPage encrypts page data with the given pgno (1-based).
func (c *Codec) EncryptPage(data []byte, pgno int) []byte {
	return EncryptPage(data, pgno, c.keystream)
}

// DecryptPage decrypts data using keystream ks according to MetaVault page rules:
// - pgno != 1: entire page XORed with ks[0..len(data)-1].
// - pgno == 1: bytes 0..15 XOR ks[0..15], bytes 16..23 clear, bytes 24.. XOR ks[0..len(data)-24-1].
func DecryptPage(data []byte, pgno int, ks []byte) []byte {
	ps := len(data)
	out := make([]byte, ps)
	if pgno != 1 {
		for i := 0; i < ps; i++ {
			out[i] = data[i] ^ ks[i]
		}
		return out
	}

	for i := 0; i < 16 && i < ps; i++ {
		out[i] = data[i] ^ ks[i]
	}
	for i := 16; i < 24 && i < ps; i++ {
		out[i] = data[i]
	}
	for i := 24; i < ps; i++ {
		out[i] = data[i] ^ ks[i-24]
	}
	return out
}

// EncryptPage encrypts data using keystream ks. Since RC4 page encryption is XOR,
// it is identical to DecryptPage.
func EncryptPage(data []byte, pgno int, ks []byte) []byte {
	return DecryptPage(data, pgno, ks)
}

// DeriveKeystream recovers the keystream from the evidence files using known header
// plaintext plus zero-filled free space voting. Returns the derived keystream and the
// count of low-confidence positions (unvoted or weak majority).
func DeriveKeystream(pages [][]byte, frames [][]byte, ps int) ([]byte, int) {
	if len(pages) == 0 {
		return nil, 0
	}

	allp := make([][]byte, 0, len(pages)+len(frames))
	allp = append(allp, pages...)
	allp = append(allp, frames...)

	key := make([]byte, ps)
	for i := 0; i < ps; i++ {
		var counts [256]int
		for _, p := range allp {
			counts[p[i]]++
		}
		bestVal := 0
		maxCount := -1
		for v := 0; v < 256; v++ {
			if counts[v] > maxCount {
				maxCount = counts[v]
				bestVal = v
			}
		}
		key[i] = byte(bestVal)
	}

	kp := make([]byte, 16)
	for i := 0; i < 16 && i < len(pages[0]) && i < len(Magic); i++ {
		kp[i] = pages[0][i] ^ Magic[i]
	}
	copy(key[:16], kp)

	nonroot := make([][]byte, 0, len(pages)-1+len(frames))
	if len(pages) > 1 {
		nonroot = append(nonroot, pages[1:]...)
	}
	nonroot = append(nonroot, frames...)

	gap := func(p []byte) (bestLen, gs, ge int) {
		s := -1
		for i := 8; i <= ps; i++ {
			m := i < ps && p[i] == key[i]
			if m && s < 0 {
				s = i
			}
			if !m && s >= 0 {
				if i-s > bestLen {
					bestLen = i - s
					gs = s
					ge = i
				}
				s = -1
			}
		}
		return bestLen, gs, ge
	}

	// Votes keep insertion order so ties resolve to the first-seen value,
	// matching Python's Counter.most_common and keeping derivation deterministic.
	var v56, v34 orderedVotes
	for _, p := range nonroot {
		t := p[0] ^ key[0]
		if t != 2 && t != 5 && t != 10 && t != 13 {
			continue
		}
		L, gs, ge := gap(p)
		if L < 16 {
			continue
		}
		hl := 8
		if t == 2 || t == 5 {
			hl = 12
		}
		k56 := [2]byte{p[5] ^ byte((ge>>8)&0xFF), p[6] ^ byte(ge&0xFF)}
		v56.add(k56)
		if (gs-hl)%2 == 0 {
			n := (gs - hl) / 2
			k34 := [2]byte{p[3] ^ byte((n>>8)&0xFF), p[4] ^ byte(n&0xFF)}
			v34.add(k34)
		}
	}

	if bestK, ok := v56.best(); ok {
		key[5] = bestK[0]
		key[6] = bestK[1]
	}

	if bestK, ok := v34.best(); ok {
		key[3] = bestK[0]
		key[4] = bestK[1]
	}

	votes := make([][256]int, ps)
	for _, p := range nonroot {
		t := p[0] ^ key[0]
		if t != 2 && t != 5 && t != 10 && t != 13 {
			continue
		}
		n := (int(p[3]^key[3]) << 8) | int(p[4]^key[4])
		cs := (int(p[5]^key[5]) << 8) | int(p[6]^key[6])
		if cs == 0 {
			cs = 65536
		}
		hl := 8
		if t == 2 || t == 5 {
			hl = 12
		}
		pe := hl + 2*n
		if pe <= cs && cs <= ps {
			for i := pe; i < cs; i++ {
				votes[i][p[i]]++
			}
		}
	}

	unvoted := 0
	lowConfidence := 0
	for i := 16; i < ps; i++ {
		if len(pages[0]) >= 92 && i >= 48 && i <= 67 {
			continue
		}
		total := 0
		bestVal := 0
		maxCount := 0
		for v := 0; v < 256; v++ {
			cnt := votes[i][v]
			total += cnt
			if cnt > maxCount {
				maxCount = cnt
				bestVal = v
			}
		}
		if total > 0 {
			key[i] = byte(bestVal)
			if total < 3 || float64(maxCount)/float64(total) < 0.75 {
				lowConfidence++
			}
		} else {
			unvoted++
		}
	}

	copy(key[:16], kp)
	if len(pages[0]) >= 92 {
		copy(key[48:68], pages[0][72:92])
	}
	return key, unvoted + lowConfidence
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// orderedVotes counts votes for 2-byte values, remembering first-seen order.
type orderedVotes struct {
	counts map[[2]byte]int
	order  [][2]byte
}

func (v *orderedVotes) add(k [2]byte) {
	if v.counts == nil {
		v.counts = make(map[[2]byte]int)
	}
	if v.counts[k] == 0 {
		v.order = append(v.order, k)
	}
	v.counts[k]++
}

// best returns the most-voted value; ties go to the value seen first.
func (v *orderedVotes) best() ([2]byte, bool) {
	var bestK [2]byte
	bestCount := 0
	for _, k := range v.order {
		if c := v.counts[k]; c > bestCount {
			bestCount, bestK = c, k
		}
	}
	return bestK, bestCount > 0
}
