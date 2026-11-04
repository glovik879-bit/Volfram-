//go:build volframandroid

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func platformPreConnect() { refreshNetInfo() }
func platformAbort()      { abortPending() }

func t2sLevel(l string) string {
	switch l {
	case "debug", "trace":
		return "info"
	case "error":
		return "error"
	}
	return "warn"
}

func (e *Engine) extUp(sv *Server, s Settings) (chan struct{}, error) {
	mtu := s.MTU
	if mtu <= 0 {
		mtu = 9000
	}
	apps := s.Apps
	if apps == nil {
		apps = []string{}
	}
	req := M{"cmd": "tun", "mtu": mtu, "ipv6": s.IPv6, "session": sv.Name, "routing": s.Routing,
		"appMode": s.AppMode, "apps": apps, "dns": "172.19.0.2"}
	e.app.Log("app", "info", "Запрос VPN-интерфейса у системы")
	_, fds, err := ctlCallX(req, 150*time.Second, true)
	if err != nil {
		return nil, err
	}
	if len(fds) == 0 {
		return nil, errors.New("система не выдала VPN-интерфейс")
	}
	closeFDs(fds[1:])
	e.vpnOn = true
	f := os.NewFile(uintptr(fds[0]), "tun")
	defer f.Close()
	proxy := fmt.Sprintf("socks5://127.0.0.1:%d", e.rp.Mixed)
	if e.rp.User != "" {
		proxy = fmt.Sprintf("socks5://%s:%s@127.0.0.1:%d", e.rp.User, e.rp.Pass, e.rp.Mixed)
	}
	args := []string{"--device", "fd://3", "--proxy", proxy,
		"--mtu", strconv.Itoa(mtu), "--loglevel", t2sLevel(s.LogLevel), "--udp-timeout", "1m"}
	cmd, err := e.startProc(filepath.Join(e.app.coreDir, exeName("tun2socks")), args, "tun2socks", nil, f)
	if err != nil {
		return nil, fmt.Errorf("не удалось запустить tun2socks: %v", err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
		return nil, errors.New("tun2socks не запустился: " + e.app.lastError("tun2socks"))
	case <-time.After(300 * time.Millisecond):
	}
	e.t2s = cmd
	return done, nil
}

func (e *Engine) extDown(stopVPN bool) {
	if e.t2s != nil && e.t2s.Process != nil {
		_ = e.t2s.Process.Kill()
	}
	e.t2s = nil
	if stopVPN && e.vpnOn {
		e.vpnOn = false
		if _, _, err := ctlCall(M{"cmd": "stop"}, 5*time.Second); err != nil {
			e.app.Log("app", "warn", "Остановка VPN: "+err.Error())
		}
	}
}
