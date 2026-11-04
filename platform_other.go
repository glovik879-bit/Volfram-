//go:build !windows && !volframandroid

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

const platformName = "dev"

func exeName(b string) string { return b }

func appDirs() (cfg, data string) {
	base := os.Getenv("VOLFRAM_HOME")
	if base == "" {
		base = filepath.Join(os.TempDir(), "volfram-dev")
	}
	return filepath.Join(base, "cfg"), filepath.Join(base, "data")
}

func hideCmd(cmd *exec.Cmd)              {}
func attachJob(cmd *exec.Cmd)            {}
func setSystemProxy(addr string) error   { return nil }
func clearSystemProxy(addr string) error { return nil }
func cleanupStaleProxy(addr string)      {}
func isAdmin() bool                      { return os.Getenv("VOLFRAM_ADMIN") == "1" || os.Geteuid() == 0 }
func setAutostart(on bool) error         { return nil }
func openURL(u string)                   {}

var devClipboard = os.Getenv("VOLFRAM_CLIP")

func readClipboard() (string, error) {
	if devClipboard == "" {
		return "", errors.New("пусто")
	}
	return devClipboard, nil
}
func writeClipboard(text string) error { devClipboard = text; return nil }

const isAndroid = false
const defaultPingMode = "get"
const defaultMode = "proxy"

func localDNS(tag string) M                     { return M{"type": "local", "tag": tag} }
func deviceInfo() (osName, osVer, model string) { return "Windows", "10", "PC" }
func listApps() (any, error) {
	return nil, errors.New("недоступно на этой платформе")
}
func appIcon(pkg string) ([]byte, error) {
	return nil, errors.New("недоступно на этой платформе")
}

func sealData(b []byte) ([]byte, error) { return b, nil }
func openData(b []byte) ([]byte, error) { return b, nil }

func beforeCoreStart(string) {}

func openVPNSettings() error { return errors.New("доступно только на Android") }
