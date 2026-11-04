//go:build windows

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var sealMagic = []byte("VOLFRAM-DPAPI-1\n")
var sealEntropy = []byte("Volfram settings v1")

func dpapi(in []byte, protect bool) ([]byte, error) {
	if len(in) == 0 {
		return nil, errors.New("empty")
	}
	inBlob := windows.DataBlob{Size: uint32(len(in)), Data: &in[0]}
	ent := windows.DataBlob{Size: uint32(len(sealEntropy)), Data: &sealEntropy[0]}
	var out windows.DataBlob
	var err error
	if protect {
		err = windows.CryptProtectData(&inBlob, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&inBlob, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return bytes.Clone(unsafe.Slice(out.Data, out.Size)), nil
}

func sealData(b []byte) ([]byte, error) {
	enc, err := dpapi(b, true)
	if err != nil {
		return nil, fmt.Errorf("шифрование настроек: %w", err)
	}
	return append(append([]byte{}, sealMagic...), enc...), nil
}

func openData(b []byte) ([]byte, error) {
	if !bytes.HasPrefix(b, sealMagic) {
		return b, nil
	}
	return dpapi(b[len(sealMagic):], false)
}

var coreHashes = map[string]string{
	"sing-box.exe":  "8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9",
	"libcronet.dll": "3217c6260fbca5f16072e0b79735742f40109a63bb0ff88fd6b96dd6b54a2928",
	"xray.exe":      "d5b558191cccb1e92a5772b68b8cab67717b26f634b0f15153215f65ae982a7e",
}

var (
	coreLockMu sync.Mutex
	coreLocks  []*os.File
)

func lockCore(path, want string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	hs := sha256.New()
	if _, err := io.Copy(hs, f); err != nil {
		f.Close()
		return nil, err
	}
	if got := hex.EncodeToString(hs.Sum(nil)); got != want {
		f.Close()
		return nil, fmt.Errorf("%s: контрольная сумма не совпадает", filepath.Base(path))
	}
	return f, nil
}

func unlockCores() {
	coreLockMu.Lock()
	defer coreLockMu.Unlock()
	for _, f := range coreLocks {
		f.Close()
	}
	coreLocks = nil
}

func lockAllCores(coreDir string) error {
	coreLockMu.Lock()
	defer coreLockMu.Unlock()
	var locks []*os.File
	for name, want := range coreHashes {
		f, err := lockCore(filepath.Join(coreDir, name), want)
		if err != nil {
			for _, l := range locks {
				l.Close()
			}
			return err
		}
		locks = append(locks, f)
	}
	coreLocks = locks
	return nil
}

func scrubCoreDir(coreDir string) {
	ents, err := os.ReadDir(coreDir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := strings.ToLower(e.Name())
		if _, ok := coreHashes[n]; ok || n == "version.txt" || n == "rules" || n == "run" {
			continue
		}
		_ = os.RemoveAll(filepath.Join(coreDir, e.Name()))
	}
}

func protectDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;OW)(A;OICI;0x1200a9;;;BU)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func beforeCoreStart(coreDir string) { scrubCoreDir(coreDir) }
