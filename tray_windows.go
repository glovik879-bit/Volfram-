//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	shell32              = windows.NewLazySystemDLL("shell32.dll")
	procShellNotifyIcon  = shell32.NewProc("Shell_NotifyIconW")
	comctl32             = windows.NewLazySystemDLL("comctl32.dll")
	procLoadIconMetric   = comctl32.NewProc("LoadIconMetric")
	procLoadImage        = user32.NewProc("LoadImageW")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenu       = user32.NewProc("AppendMenuW")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procSetMenuDefault   = user32.NewProc("SetMenuDefaultItem")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procCallWindowProc   = user32.NewProc("CallWindowProcW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procRegisterMsg      = user32.NewProc("RegisterWindowMessageW")
	procMsgFilterEx      = user32.NewProc("ChangeWindowMessageFilterEx")
	procIsWindowVisible  = user32.NewProc("IsWindowVisible")
	procAllowSetFg       = user32.NewProc("AllowSetForegroundWindow")
)

const (
	wmNull          = 0x0000
	wmDestroy       = 0x0002
	wmEndSession    = 0x0016
	wmContextMenu   = 0x007B
	wmLButtonUp     = 0x0202
	wmRButtonUp     = 0x0205
	wmTrayIcon      = 0x8001
	wmTrayRefresh   = 0x8002
	ninBalloonClick = 0x0405
	nimAdd          = 0
	nimModify       = 1
	nimDelete       = 2
	nifMessage      = 0x01
	nifIcon         = 0x02
	nifTip          = 0x04
	nifInfo         = 0x10
	niifInfo        = 0x01
	niifWarning     = 0x02
	niifQuiet       = 0x80
	mfGrayed        = 0x0001
	mfChecked       = 0x0008
	mfPopup         = 0x0010
	mfSeparator     = 0x0800
	mftRadio        = 0x0200
	tpmRightButton  = 0x0002
	tpmNoNotify     = 0x0080
	tpmReturnCmd    = 0x0100
	swHide          = 0
	swShow          = 5
	wsExToolWindow  = 0x00000080
	gwlpWndProc     = ^uintptr(3)
	cmdOpen         = 1
	cmdToggle       = 2
	cmdQuit         = 3
	cmdServer       = 100
	trayMaxServers  = 60
	showMsgName     = "Volfram.ShowWindow"
)

type notifyIconData struct {
	Size        uint32
	Wnd         uintptr
	ID          uint32
	Flags       uint32
	CallbackMsg uint32
	Icon        uintptr
	Tip         [128]uint16
	State       uint32
	StateMask   uint32
	Info        [256]uint16
	Version     uint32
	InfoTitle   [64]uint16
	InfoFlags   uint32
	GUID        windows.GUID
	BalloonIcon uintptr
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type balloon struct {
	title, text string
	flags       uint32
}

type trayIcon struct {
	app        *App
	ws         *winState
	hwnd       uintptr
	prevProc   uintptr
	icons      [3]uintptr
	added      bool
	quitting   atomic.Bool
	quit       func()
	taskbarMsg uintptr
	showMsg    uintptr
	lastState  string
	lastErr    string
	wasUp      bool
	mu         sync.Mutex
	pending    []balloon
}

var theTray *trayIcon

func registerMsg(name string) uintptr {
	m, _, _ := procRegisterMsg.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))))
	return m
}

func utf16Fit(dst []uint16, s string) {
	u := utf16.Encode([]rune(s))
	if len(u) > len(dst)-1 {
		u = u[:len(dst)-1]
		if n := len(u); n > 0 && u[n-1] >= 0xD800 && u[n-1] < 0xDC00 {
			u = u[:n-1]
		}
	}
	copy(dst, u)
	dst[len(u)] = 0
}

func cut(s string, n int) string {
	r := []rune(strings.Join(strings.Fields(s), " "))
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return string(r)
}

func loadIconRes(inst uintptr, id int) uintptr {
	var h uintptr
	if procLoadIconMetric.Find() == nil {
		if r, _, _ := procLoadIconMetric.Call(inst, uintptr(id), 0, uintptr(unsafe.Pointer(&h))); r == 0 && h != 0 {
			return h
		}
	}
	cx, _, _ := procGetSystemMetrics.Call(49)
	cy, _, _ := procGetSystemMetrics.Call(50)
	h, _, _ = procLoadImage.Call(inst, uintptr(id), 1, cx, cy, 0)
	return h
}

func darkMenus() {
	v := windows.RtlGetVersion()
	if v.MajorVersion < 10 || v.BuildNumber < 18362 {
		return
	}
	h, err := windows.LoadLibraryEx("uxtheme.dll", 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return
	}
	if p, err := windows.GetProcAddressByOrdinal(h, 135); err == nil {
		syscall.SyscallN(p, 1)
	}
	if p, err := windows.GetProcAddressByOrdinal(h, 136); err == nil {
		syscall.SyscallN(p)
	}
}

func newTray(app *App, ws *winState, quit func()) *trayIcon {
	t := &trayIcon{app: app, ws: ws, quit: quit}
	theTray = t
	var inst windows.Handle
	_ = windows.GetModuleHandleEx(0, nil, &inst)
	cb := windows.NewCallback(trayWndProc)
	cls := windows.StringToUTF16Ptr("VolframTray")
	wc := wndClassEx{WndProc: cb, Instance: uintptr(inst), ClassName: cls}
	wc.Size = uint32(unsafe.Sizeof(wc))
	procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))
	t.hwnd, _, _ = procCreateWindowEx.Call(wsExToolWindow, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("Volfram Tray"))), wsPopup, 0, 0, 0, 0, 0, 0, uintptr(inst), 0)
	t.taskbarMsg = registerMsg("TaskbarCreated")
	t.showMsg = registerMsg(showMsgName)
	if procMsgFilterEx.Find() == nil {
		for _, h := range []uintptr{t.hwnd, ws.hwnd} {
			for _, m := range []uintptr{t.taskbarMsg, t.showMsg} {
				if h != 0 && m != 0 {
					procMsgFilterEx.Call(h, m, 1, 0)
				}
			}
		}
	}
	for i := range t.icons {
		t.icons[i] = loadIconRes(uintptr(inst), i+1)
		if t.icons[i] == 0 {
			t.icons[i] = loadIconRes(uintptr(inst), 1)
		}
	}
	darkMenus()
	t.prevProc, _, _ = procSetWindowLongPtr.Call(ws.hwnd, gwlpWndProc, cb)
	app.hooks.Store(&appHooks{
		status: func(Status) { t.post() },
		needAdmin: func() {
			if t.showMsg != 0 {
				procPostMessage.Call(t.ws.hwnd, t.showMsg, 0, 0)
			}
		},
	})
	t.refresh()
	return t
}

func trayWndProc(hwnd, msg, wp, lp uintptr) uintptr {
	t := theTray
	if t == nil {
		r, _, _ := procDefWindowProc.Call(hwnd, msg, wp, lp)
		return r
	}
	if hwnd == t.ws.hwnd {
		switch {
		case msg == wmClose && !t.quitting.Load() && t.app.closeToTray():
			t.hide(true)
			return 0
		case msg == t.showMsg && msg != 0:
			t.show()
			return 0
		case msg == wmEndSession && wp != 0:
			t.remove()
			t.app.Shutdown()
		}
		r, _, _ := procCallWindowProc.Call(t.prevProc, hwnd, msg, wp, lp)
		return r
	}
	if hwnd == t.hwnd {
		switch {
		case msg == wmTrayIcon:
			switch lp & 0xFFFF {
			case wmLButtonUp, ninBalloonClick:
				t.show()
			case wmRButtonUp, wmContextMenu:
				t.menu()
			}
			return 0
		case msg == wmTrayRefresh:
			t.refresh()
			return 0
		case msg == t.taskbarMsg && msg != 0:
			t.added = false
			t.refresh()
			return 0
		}
	}
	r, _, _ := procDefWindowProc.Call(hwnd, msg, wp, lp)
	return r
}

func (a *App) closeToTray() bool {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	return a.store.Settings.CloseToTray
}

func (t *trayIcon) post() {
	if t.hwnd != 0 {
		procPostMessage.Call(t.hwnd, wmTrayRefresh, 0, 0)
	}
}

func (t *trayIcon) notify(title, text string, flags uint32) {
	t.mu.Lock()
	t.pending = append(t.pending, balloon{title, text, flags})
	t.mu.Unlock()
	t.post()
}

func (t *trayIcon) visible() bool {
	v, _, _ := procIsWindowVisible.Call(t.ws.hwnd)
	ic, _, _ := procIsIconic.Call(t.ws.hwnd)
	return v != 0 && ic == 0
}

func (t *trayIcon) show() {
	h := t.ws.hwnd
	if v, _, _ := procIsWindowVisible.Call(h); v == 0 {
		procShowWindow.Call(h, swShow)
	}
	if ic, _, _ := procIsIconic.Call(h); ic != 0 {
		procShowWindow.Call(h, swRestore)
	}
	procSetForeground.Call(h)
}

func (t *trayIcon) hide(hint bool) {
	if !t.added {
		procShowWindow.Call(t.ws.hwnd, swMinimize)
		return
	}
	procShowWindow.Call(t.ws.hwnd, swHide)
	if !hint {
		return
	}
	mark := filepath.Join(t.app.dataDir, "tray-hint")
	if _, err := os.Stat(mark); err == nil {
		return
	}
	_ = os.WriteFile(mark, []byte("1"), 0o600)
	t.notify("Volfram работает в трее", "VPN не отключается при закрытии окна. Открыть — щелчок по значку, выход — через его меню.", niifInfo|niifQuiet)
}

func (t *trayIcon) nid() notifyIconData {
	d := notifyIconData{Wnd: t.hwnd, ID: 1}
	d.Size = uint32(unsafe.Sizeof(d))
	return d
}

func (t *trayIcon) remove() {
	if !t.added {
		return
	}
	d := t.nid()
	procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&d)))
	t.added = false
}

func stateText(st string) string {
	switch st {
	case "connected":
		return "Подключено"
	case "connecting":
		return "Подключение…"
	case "stopping":
		return "Отключение…"
	}
	return "Отключено"
}

func (a *App) serverName(id string) string {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	if sv := a.store.find(id); sv != nil {
		return sv.Name
	}
	return ""
}

func (t *trayIcon) refresh() {
	if t.hwnd == 0 || t.quitting.Load() {
		return
	}
	st := t.app.engine.Status()
	idx := 1
	switch st.State {
	case "connected":
		idx = 0
	case "connecting", "stopping":
		idx = 2
	}
	tip := "Volfram — " + stateText(st.State)
	if st.State == "connected" {
		if st.Mode == "tun" {
			tip += " (TUN)"
		} else {
			tip += " (прокси)"
		}
	}
	if st.State != "idle" {
		if n := t.app.serverName(st.ServerID); n != "" {
			tip += "\n" + cut(n, 60)
		}
	}
	d := t.nid()
	d.Flags = nifMessage | nifIcon | nifTip
	d.CallbackMsg = wmTrayIcon
	d.Icon = t.icons[idx]
	utf16Fit(d.Tip[:], tip)
	call := func(op uintptr) bool {
		r, _, _ := procShellNotifyIcon.Call(op, uintptr(unsafe.Pointer(&d)))
		return r != 0
	}
	ok := t.added && call(nimModify)
	if !ok {
		ok = call(nimAdd) || call(nimModify)
	}
	t.added = ok
	if st.State == "idle" && st.Error != "" && (t.lastState != "idle" || t.lastErr != st.Error) && !t.visible() {
		title := "Не удалось подключиться"
		if t.wasUp {
			title = "Соединение разорвано"
		}
		t.mu.Lock()
		t.pending = append(t.pending, balloon{title, cut(st.Error, 200), niifWarning})
		t.mu.Unlock()
	}
	switch st.State {
	case "connected":
		t.wasUp = true
	case "idle":
		t.wasUp = false
	}
	t.lastState, t.lastErr = st.State, st.Error
	t.mu.Lock()
	q := t.pending
	t.pending = nil
	t.mu.Unlock()
	if !t.added {
		return
	}
	for _, b := range q {
		n := t.nid()
		n.Flags = nifInfo
		n.InfoFlags = b.flags
		utf16Fit(n.InfoTitle[:], b.title)
		utf16Fit(n.Info[:], b.text)
		procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&n)))
	}
}

func menuText(s string) string {
	return strings.ReplaceAll(s, "&", "&&")
}

func (t *trayIcon) menu() {
	st := t.app.engine.Status()
	m, _, _ := procCreatePopupMenu.Call()
	if m == 0 {
		return
	}
	defer procDestroyMenu.Call(m)
	add := func(menu, flags, id uintptr, text string) {
		var p uintptr
		if flags&mfSeparator == 0 {
			p = uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(text)))
		}
		procAppendMenu.Call(menu, flags, id, p)
	}
	head := stateText(st.State)
	if st.State != "idle" {
		if n := t.app.serverName(st.ServerID); n != "" {
			head += " · " + cut(n, 40)
		}
	}
	add(m, mfGrayed, 0, menuText(head))
	add(m, mfSeparator, 0, "")
	add(m, 0, cmdOpen, "Открыть Volfram")
	switch st.State {
	case "connected", "connecting":
		add(m, 0, cmdToggle, "Отключить")
	case "stopping":
		add(m, mfGrayed, cmdToggle, "Отключение…")
	default:
		add(m, 0, cmdToggle, "Подключить")
	}
	t.app.store.mu.Lock()
	sel := t.app.store.Selected
	type item struct {
		id, name string
		delay    int
	}
	var list []item
	total := len(t.app.store.Servers)
	for _, sv := range t.app.store.Servers {
		if len(list) == trayMaxServers {
			break
		}
		list = append(list, item{sv.ID, sv.Name, sv.Delay})
	}
	t.app.store.mu.Unlock()
	sub, _, _ := procCreatePopupMenu.Call()
	if sub != 0 {
		for i, it := range list {
			flags := uintptr(mftRadio)
			if it.id == sel {
				flags |= mfChecked
			}
			text := menuText(cut(it.name, 48))
			if it.delay > 0 {
				text += "\t" + strconv.Itoa(it.delay) + " мс"
			}
			add(sub, flags, uintptr(cmdServer+i), text)
		}
		if len(list) == 0 {
			add(sub, mfGrayed, 0, "Нет серверов")
		} else if total > len(list) {
			add(sub, mfSeparator, 0, "")
			add(sub, mfGrayed, 0, "Ещё "+strconv.Itoa(total-len(list))+" — в окне программы")
		}
		add(m, mfPopup, sub, "Сервер")
	}
	add(m, mfSeparator, 0, "")
	add(m, 0, cmdQuit, "Выход")
	procSetMenuDefault.Call(m, cmdOpen, 0)
	var pt struct{ X, Y int32 }
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForeground.Call(t.hwnd)
	cmd, _, _ := procTrackPopupMenu.Call(m, tpmRightButton|tpmNoNotify|tpmReturnCmd, uintptr(pt.X), uintptr(pt.Y), 0, t.hwnd, 0)
	procPostMessage.Call(t.hwnd, wmNull, 0, 0)
	switch {
	case cmd == cmdOpen:
		t.show()
	case cmd == cmdToggle:
		if st.State == "connected" || st.State == "connecting" {
			go t.app.engine.Disconnect()
		} else {
			go t.connect()
		}
	case cmd == cmdQuit:
		t.quit()
	case cmd >= cmdServer && int(cmd-cmdServer) < len(list):
		id := list[cmd-cmdServer].id
		go func() {
			if !t.app.selectServer(id) {
				return
			}
			if s := t.app.engine.Status(); s.State == "connected" && s.ServerID == id {
				return
			}
			t.connect()
		}()
	}
}

func (t *trayIcon) connect() {
	err := t.app.Connect()
	if err == nil || err == ErrCancelled {
		return
	}
	if err == ErrNeedAdmin {
		t.app.needAdmin()
		return
	}
	t.app.hub.Send("toast", M{"kind": "error", "text": err.Error()})
	if t.app.engine.Status().Error != err.Error() {
		t.notify("Не удалось подключиться", cut(err.Error(), 200), niifWarning)
	}
}
