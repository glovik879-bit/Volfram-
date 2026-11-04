//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const platformName = "windows"

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	wininet          = windows.NewLazySystemDLL("wininet.dll")
	procOpenClip     = user32.NewProc("OpenClipboard")
	procCloseClip    = user32.NewProc("CloseClipboard")
	procEmptyClip    = user32.NewProc("EmptyClipboard")
	procGetClipData  = user32.NewProc("GetClipboardData")
	procSetClipData  = user32.NewProc("SetClipboardData")
	procGlobalAlloc  = kernel32.NewProc("GlobalAlloc")
	procGlobalLock   = kernel32.NewProc("GlobalLock")
	procGlobalUnlock = kernel32.NewProc("GlobalUnlock")
	procRegClipFmt   = user32.NewProc("RegisterClipboardFormatW")
	procInetSetOpt   = wininet.NewProc("InternetSetOptionW")
	jobHandle        windows.Handle
	mainHWND         uintptr
)

func exeName(b string) string { return b + ".exe" }

func appDirs() (cfg, data string) {
	cfg = filepath.Join(os.Getenv("APPDATA"), "Volfram")
	data = filepath.Join(os.Getenv("LOCALAPPDATA"), "Volfram")
	if os.Getenv("APPDATA") == "" {
		d, _ := os.UserConfigDir()
		cfg = filepath.Join(d, "Volfram")
	}
	if os.Getenv("LOCALAPPDATA") == "" {
		d, _ := os.UserCacheDir()
		data = filepath.Join(d, "Volfram")
	}
	return
}

func hideCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

func initJob() {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err != nil {
		windows.CloseHandle(h)
		return
	}
	jobHandle = h
}

func attachJob(cmd *exec.Cmd) {
	if jobHandle == 0 || cmd.Process == nil {
		return
	}
	ph, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return
	}
	_ = windows.AssignProcessToJobObject(jobHandle, ph)
	windows.CloseHandle(ph)
}

const inetKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

var prevProxy struct {
	saved    bool
	enable   uint64
	server   string
	override string
}

func refreshInet() {
	procInetSetOpt.Call(0, 39, 0, 0)
	procInetSetOpt.Call(0, 37, 0, 0)
}

func setSystemProxy(addr string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, inetKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !prevProxy.saved {
		prevProxy.enable, _, _ = k.GetIntegerValue("ProxyEnable")
		prevProxy.server, _, _ = k.GetStringValue("ProxyServer")
		prevProxy.override, _, _ = k.GetStringValue("ProxyOverride")
		if prevProxy.server == addr {
			prevProxy.enable, prevProxy.server = 0, ""
		}
		prevProxy.saved = true
	}
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	_ = k.SetStringValue("ProxyServer", addr)
	_ = k.SetStringValue("ProxyOverride", "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>")
	refreshInet()
	return nil
}

func clearSystemProxy(addr string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	cur, _, _ := k.GetStringValue("ProxyServer")
	if cur != addr && addr != "" {
		return nil
	}
	if prevProxy.saved && prevProxy.enable == 1 && prevProxy.server != "" {
		_ = k.SetStringValue("ProxyServer", prevProxy.server)
		_ = k.SetStringValue("ProxyOverride", prevProxy.override)
		_ = k.SetDWordValue("ProxyEnable", 1)
	} else {
		_ = k.SetDWordValue("ProxyEnable", 0)
		if prevProxy.saved {
			_ = k.SetStringValue("ProxyServer", prevProxy.server)
		}
	}
	prevProxy.saved = false
	refreshInet()
	return nil
}

func cleanupStaleProxy(addr string) {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	en, _, _ := k.GetIntegerValue("ProxyEnable")
	cur, _, _ := k.GetStringValue("ProxyServer")
	if en == 1 && cur == addr {
		_ = k.SetDWordValue("ProxyEnable", 0)
		refreshInet()
	}
}

func isAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func openClipboard() bool {
	for i := 0; i < 10; i++ {
		if r, _, _ := procOpenClip.Call(mainHWND); r != 0 {
			return true
		}
		time.Sleep(30 * time.Millisecond)
	}
	return false
}

func readClipboard() (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !openClipboard() {
		return "", errors.New("буфер обмена занят")
	}
	defer procCloseClip.Call()
	h, _, _ := procGetClipData.Call(13)
	if h == 0 {
		return "", errors.New("в буфере нет текста")
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return "", errors.New("не удалось прочитать буфер")
	}
	defer procGlobalUnlock.Call(h)
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(p))), nil
}

func writeClipboard(text string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	u, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	if !openClipboard() {
		return errors.New("буфер обмена занят")
	}
	defer procCloseClip.Call()
	procEmptyClip.Call()
	size := uintptr(len(u) * 2)
	h, _, _ := procGlobalAlloc.Call(0x0002, size)
	if h == 0 {
		return errors.New("нет памяти")
	}
	p, _, _ := procGlobalLock.Call(h)
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(p)), len(u)), u)
	procGlobalUnlock.Call(h)
	if r, _, _ := procSetClipData.Call(13, h); r == 0 {
		return errors.New("не удалось записать в буфер")
	}
	markClipboardPrivate()
	return nil
}

func markClipboardPrivate() {
	set := func(name string, val uint32) {
		n, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return
		}
		f, _, _ := procRegClipFmt.Call(uintptr(unsafe.Pointer(n)))
		if f == 0 {
			return
		}
		h, _, _ := procGlobalAlloc.Call(0x0002, 4)
		if h == 0 {
			return
		}
		if p, _, _ := procGlobalLock.Call(h); p != 0 {
			*(*uint32)(unsafe.Pointer(p)) = val
			procGlobalUnlock.Call(h)
			procSetClipData.Call(f, h)
		}
	}
	set("ExcludeClipboardContentFromMonitorProcessing", 0)
	set("CanIncludeInClipboardHistory", 0)
	set("CanUploadToCloudClipboard", 0)
}

func setAutostart(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		err := k.DeleteValue("Volfram")
		if err != nil && !strings.Contains(err.Error(), "cannot find") {
			return nil
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return k.SetStringValue("Volfram", `"`+exe+`" --autostart`)
}

func openVPNSettings() error { return errors.New("доступно только на Android") }

func openURL(u string) {
	_ = windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(u), nil, nil, windows.SW_SHOWNORMAL)
}

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
