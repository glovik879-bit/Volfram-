package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestCoreHashes(t *testing.T) {
	src, err := os.ReadFile("secure_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`"([a-z.-]+\.(?:exe|dll))":\s+"([0-9a-f]{64})"`)
	m := re.FindAllStringSubmatch(string(src), -1)
	if len(m) != 3 {
		t.Fatalf("expected 3 hashes, got %d", len(m))
	}
	for _, x := range m {
		z, err := os.ReadFile("assets/" + x[1] + ".zst")
		if err != nil {
			t.Fatal(err)
		}
		d, _ := zstd.NewReader(nil, zstd.WithDecoderMaxWindow(1<<30))
		b, err := d.DecodeAll(z, nil)
		d.Close()
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != x[2] {
			t.Errorf("%s: hash mismatch, update secure_windows.go", x[1])
		}
	}
}
