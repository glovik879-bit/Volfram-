//go:build windows

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
)

const SingboxVersion = "1.14.4"
const XrayVersion = "26.10.31"
const coreStamp = "sb-1.14.4+xray-26.10.31+r1"

//go:embed assets/sing-box.exe.zst
var zSingbox []byte

//go:embed assets/libcronet.dll.zst
var zCronet []byte

//go:embed assets/xray.exe.zst
var zXray []byte

func extractOne(dst string, data []byte) error {
	dec, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderMaxWindow(1<<30))
	if err != nil {
		return err
	}
	defer dec.Close()
	tmp := dst + ".new"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, dec); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	_ = os.Remove(dst)
	return os.Rename(tmp, dst)
}

func extractCores(coreDir, rulesDir string) error {
	if err := os.MkdirAll(coreDir, 0o700); err != nil {
		return err
	}
	if isAdmin() {
		if err := protectDir(coreDir); err != nil {
			fmt.Fprintln(os.Stderr, "protect cores dir:", err)
		}
	}
	if err := writeRules(rulesDir); err != nil {
		return err
	}
	scrubCoreDir(coreDir)
	stamp := filepath.Join(coreDir, "version.txt")
	files := map[string][]byte{"sing-box.exe": zSingbox, "libcronet.dll": zCronet, "xray.exe": zXray}
	if b, err := os.ReadFile(stamp); err == nil && string(b) == coreStamp {
		if lockAllCores(coreDir) == nil {
			return nil
		}
	}
	unlockCores()
	for name, data := range files {
		if err := extractOne(filepath.Join(coreDir, name), data); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := lockAllCores(coreDir); err != nil {
		return err
	}
	return os.WriteFile(stamp, []byte(coreStamp), 0o600)
}
