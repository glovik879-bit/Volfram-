//go:build volframandroid

package main

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const platformName = "android"
const isAndroid = true
const defaultPingMode = "tcp"
const defaultMode = "tun"

func exeName(b string) string { return "lib" + strings.ReplaceAll(b, "-", "") + ".so" }

func appDirs() (cfg, data string) {
	base := os.Getenv("VOLFRAM_HOME")
	if base == "" {
		base = filepath.Join(os.TempDir(), "volfram-android")
	}
	return filepath.Join(base, "cfg"), filepath.Join(base, "data")
}

func hideCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
func attachJob(cmd *exec.Cmd)            {}
func setSystemProxy(addr string) error   { return nil }
func clearSystemProxy(addr string) error { return nil }
func cleanupStaleProxy(addr string)      {}
func isAdmin() bool                      { return true }
func setAutostart(on bool) error         { return nil }

func openURL(u string) {
	go func() { _, _, _ = ctlCall(M{"cmd": "open", "url": u}, 5*time.Second) }()
}

func readClipboard() (string, error) {
	r, _, err := ctlCall(M{"cmd": "paste"}, 5*time.Second)
	if err != nil {
		return "", err
	}
	t, _ := r["text"].(string)
	if strings.TrimSpace(t) == "" {
		return "", errors.New("буфер обмена пуст")
	}
	return t, nil
}

func writeClipboard(text string) error {
	_, _, err := ctlCall(M{"cmd": "copy", "text": text}, 5*time.Second)
	return err
}

func deviceInfo() (osName, osVer, model string) {
	v, m := os.Getenv("VOLFRAM_OS_VER"), os.Getenv("VOLFRAM_DEVICE_MODEL")
	if v == "" {
		v = "14"
	}
	if m == "" {
		m = "Android"
	}
	return "Android", v, m
}

var usedLocalDNS atomic.Value

func localDNS(tag string) M {
	d := sysDNS()[0]
	usedLocalDNS.Store(d)
	return M{"type": "udp", "tag": tag, "server": d}
}

func listApps() (any, error) {
	r, _, err := ctlCall(M{"cmd": "apps"}, 30*time.Second)
	if err != nil {
		return nil, err
	}
	return r["apps"], nil
}

func appIcon(pkg string) ([]byte, error) {
	if pkg == "" {
		return nil, errors.New("pkg")
	}
	r, _, err := ctlCall(M{"cmd": "icon", "pkg": pkg}, 8*time.Second)
	if err != nil {
		return nil, err
	}
	s, _ := r["png"].(string)
	return base64.StdEncoding.DecodeString(s)
}

func sealData(b []byte) ([]byte, error) { return b, nil }
func openData(b []byte) ([]byte, error) { return b, nil }

func beforeCoreStart(string) {}

func openVPNSettings() error {
	_, _, err := ctlCall(M{"cmd": "vpnsettings"}, 5*time.Second)
	return err
}
