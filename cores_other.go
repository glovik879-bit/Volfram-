//go:build !windows && !volframandroid

package main

import (
	"os"
	"path/filepath"
)

const SingboxVersion = "1.14.4"
const XrayVersion = "26.10.31"

func extractCores(coreDir, rulesDir string) error {
	if err := os.MkdirAll(coreDir, 0o755); err != nil {
		return err
	}
	if err := writeRules(rulesDir); err != nil {
		return err
	}
	src := os.Getenv("VOLFRAM_CORES")
	for _, n := range []string{"sing-box", "xray", "libcronet.so"} {
		dst := filepath.Join(coreDir, n)
		_ = os.Remove(dst)
		if err := os.Symlink(filepath.Join(src, n), dst); err != nil {
			return err
		}
	}
	return nil
}
