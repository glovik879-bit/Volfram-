//go:build windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

var (
	dwmapi                = windows.NewLazySystemDLL("dwmapi.dll")
	procDwmSetAttr        = dwmapi.NewProc("DwmSetWindowAttribute")
	procSetWindowLongPtr  = user32.NewProc("SetWindowLongPtrW")
	procGetWindowLongPtr  = user32.NewProc("GetWindowLongPtrW")
	procSetClassLongPtr   = user32.NewProc("SetClassLongPtrW")
	procGetClassLongPtr   = user32.NewProc("GetClassLongPtrW")
	procSetWindowPos      = user32.NewProc("SetWindowPos")
	procGetDpiForWindow   = user32.NewProc("GetDpiForWindow")
	procReleaseCapture    = user32.NewProc("ReleaseCapture")
	procPostMessage       = user32.NewProc("PostMessageW")
	procShowWindow        = user32.NewProc("ShowWindow")
	procFindWindow        = user32.NewProc("FindWindowW")
	procSetForeground     = user32.NewProc("SetForegroundWindow")
	procMessageBox        = user32.NewProc("MessageBoxW")
	procMonitorFromWindow = user32.NewProc("MonitorFromWindow")
	procGetMonitorInfo    = user32.NewProc("GetMonitorInfoW")
	procGetWindowRect     = user32.NewProc("GetWindowRect")
	procIsIconic          = user32.NewProc("IsIconic")
)

const (
	gwlStyle        = ^uintptr(15)
	wsPopup         = 0x80000000
	wsVisible       = 0x10000000
	wsClipChildren  = 0x02000000
	wsMinimizeBox   = 0x00020000
	wsSysMenu       = 0x00080000
	swpNoZOrder     = 0x0004
	swpFrameChanged = 0x0020
	swpNoActivate   = 0x0010
	wmClose         = 0x0010
	wmNCLButtonDown = 0x00A1
	htCaption       = 2
	swMinimize      = 6
	swRestore       = 9
	gclStyle        = ^uintptr(25)
	csDropShadow    = 0x00020000
)

type rect struct{ L, T, R, B int32 }
type monitorInfo struct {
	Size    uint32
	Monitor rect
	Work    rect
	Flags   uint32
}

const appTitle = "Volfram"

func msgBox(text string, flags uintptr) {
	procMessageBox.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(text))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(appTitle))), flags)
}

func workArea(hwnd uintptr) rect {
	mon, _, _ := procMonitorFromWindow.Call(hwnd, 2)
	mi := monitorInfo{Size: uint32(unsafe.Sizeof(monitorInfo{}))}
	procGetMonitorInfo.Call(mon, uintptr(unsafe.Pointer(&mi)))
	return mi.Work
}

func setDwm(hwnd uintptr, attr uintptr, val uint32) {
	procDwmSetAttr.Call(hwnd, attr, uintptr(unsafe.Pointer(&val)), 4)
}

type winState struct {
	hwnd      uintptr
	maximized bool
	restore   rect
}

func (ws *winState) styleFrameless(logicalW, logicalH int) {
	h := ws.hwnd
	procSetWindowLongPtr.Call(h, gwlStyle, wsPopup|wsVisible|wsClipChildren|wsMinimizeBox|wsSysMenu)
	cs, _, _ := procGetClassLongPtr.Call(h, gclStyle)
	procSetClassLongPtr.Call(h, gclStyle, cs|csDropShadow)
	setDwm(h, 20, 1)
	setDwm(h, 33, 2)
	setDwm(h, 34, 0x00241C1C)
	dpi := uintptr(96)
	if procGetDpiForWindow.Find() == nil {
		if d, _, _ := procGetDpiForWindow.Call(h); d > 0 {
			dpi = d
		}
	}
	w := int32(logicalW * int(dpi) / 96)
	hh := int32(logicalH * int(dpi) / 96)
	wa := workArea(h)
	aw, ah := wa.R-wa.L, wa.B-wa.T
	if w > aw*96/100 {
		w = aw * 96 / 100
	}
	if hh > ah*94/100 {
		hh = ah * 94 / 100
	}
	x := wa.L + (aw-w)/2
	y := wa.T + (ah-hh)/2
	procSetWindowPos.Call(h, 0, uintptr(x), uintptr(y), uintptr(w), uintptr(hh), swpNoZOrder|swpFrameChanged)
}

func (ws *winState) toggleMax() {
	h := ws.hwnd
	if ws.maximized {
		r := ws.restore
		procSetWindowPos.Call(h, 0, uintptr(r.L), uintptr(r.T), uintptr(r.R-r.L), uintptr(r.B-r.T), swpNoZOrder)
		setDwm(h, 33, 2)
		ws.maximized = false
		return
	}
	procGetWindowRect.Call(h, uintptr(unsafe.Pointer(&ws.restore)))
	wa := workArea(h)
	setDwm(h, 33, 1)
	procSetWindowPos.Call(h, 0, uintptr(wa.L), uintptr(wa.T), uintptr(wa.R-wa.L), uintptr(wa.B-wa.T), swpNoZOrder)
	ws.maximized = true
}

func hasArg(a string) bool {
	for _, x := range os.Args[1:] {
		if strings.EqualFold(x, a) {
			return true
		}
	}
	return false
}

func main() {
	runtime.LockOSThread()
	elevated := hasArg("--elevated")
	autostart := hasArg("--autostart")
	connect := hasArg("--connect")

	name := windows.StringToUTF16Ptr(`Local\Volfram.SingleInstance`)
	var mutex windows.Handle
	var err error
	for i := 0; ; i++ {
		mutex, err = windows.CreateMutex(nil, false, name)
		if err == nil {
			break
		}
		if err == windows.ERROR_ALREADY_EXISTS {
			if mutex != 0 {
				windows.CloseHandle(mutex)
			}
			if elevated && i < 60 {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			if h, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("webview"))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(appTitle)))); h != 0 {
				procAllowSetFg.Call(0xFFFFFFFF)
				if m := registerMsg(showMsgName); m != 0 {
					if r, _, _ := procPostMessage.Call(h, m, 0, 0); r != 0 {
						return
					}
				}
				procShowWindow.Call(h, swRestore)
				procSetForeground.Call(h)
			}
			return
		}
		break
	}
	defer windows.CloseHandle(mutex)

	initJob()
	cfgDir, dataDir := appDirs()
	_ = os.MkdirAll(cfgDir, 0o700)
	_ = os.MkdirAll(dataDir, 0o700)
	app := NewApp(cfgDir, dataDir)
	if isAdmin() {
		app.coreDir = filepath.Join(dataDir, "core-admin")
		app.rulesDir = filepath.Join(app.coreDir, "rules")
		app.runDir = filepath.Join(app.coreDir, "run")
	}
	u, err := app.Serve()
	if err != nil {
		msgBox("Не удалось запустить интерфейс: "+err.Error(), 0x10)
		return
	}

	os.Setenv("WEBVIEW2_DEFAULT_BACKGROUND_COLOR", "FF07070A")
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     os.Getenv("VOLFRAM_DEBUG") == "1",
		AutoFocus: true,
		DataPath:  filepath.Join(dataDir, "webview"),
		WindowOptions: webview2.WindowOptions{
			Title:  appTitle,
			Width:  1220,
			Height: 780,
			IconId: 1,
			Center: true,
		},
	})
	if w == nil {
		app.Shutdown()
		msgBox("Для работы Volfram нужен компонент Microsoft Edge WebView2 Runtime.\n\nСейчас откроется страница загрузки — установите «Evergreen Bootstrapper» и запустите программу снова.", 0x30)
		openURL("https://developer.microsoft.com/microsoft-edge/webview2/#download")
		return
	}
	ws := &winState{hwnd: uintptr(w.Window())}
	mainHWND = ws.hwnd
	ws.styleFrameless(1220, 780)

	closeWin := func() { procPostMessage.Call(ws.hwnd, wmClose, 0, 0) }
	var tr *trayIcon
	quit := func() {
		if tr != nil {
			tr.quitting.Store(true)
		}
		closeWin()
	}
	_ = w.Bind("__volframDrag", func() {
		if ws.maximized {
			return
		}
		procReleaseCapture.Call()
		procPostMessage.Call(ws.hwnd, wmNCLButtonDown, htCaption, 0)
	})
	_ = w.Bind("__volframMin", func() { procShowWindow.Call(ws.hwnd, swMinimize) })
	_ = w.Bind("__volframMax", func() bool { ws.toggleMax(); return ws.maximized })
	_ = w.Bind("__volframClose", func() { closeWin() })
	_ = w.Bind("__volframQuit", func() { quit() })
	app.onQuit = func() { w.Dispatch(quit) }
	app.onRestartAdmin = func() error {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		cwd, _ := os.Getwd()
		err = windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr(exe), windows.StringToUTF16Ptr("--elevated --connect"), windows.StringToUTF16Ptr(cwd), windows.SW_SHOWNORMAL)
		if err != nil {
			return err
		}
		go func() {
			app.Shutdown()
			w.Dispatch(quit)
		}()
		return nil
	}
	tr = newTray(app, ws, quit)
	app.StartBackground(connect)
	w.Navigate(u)
	if autostart {
		tr.hide(false)
	}
	w.Run()
	tr.remove()
	app.Shutdown()
}
