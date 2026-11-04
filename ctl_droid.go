//go:build volframandroid

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var ctlName = os.Getenv("VOLFRAM_CTL")

func ctlDial() (*net.UnixConn, error) {
	if ctlName == "" {
		return nil, errors.New("нет связи с приложением")
	}
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: "@" + ctlName, Net: "unix"})
	if err != nil {
		return nil, err
	}
	var uid uint32 = ^uint32(0)
	if rc, err := c.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) {
			if cr, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); err == nil {
				uid = cr.Uid
			}
		})
	}
	if uid != uint32(os.Getuid()) {
		c.Close()
		return nil, errors.New("чужой управляющий сокет")
	}
	return c, nil
}

func ctlCall(req M, timeout time.Duration) (M, []int, error) { return ctlCallX(req, timeout, false) }

var (
	pendMu   sync.Mutex
	pendConn *net.UnixConn
)

func abortPending() {
	pendMu.Lock()
	if pendConn != nil {
		_ = pendConn.Close()
		pendConn = nil
	}
	pendMu.Unlock()
}

func ctlCallX(req M, timeout time.Duration, abortable bool) (M, []int, error) {
	c, err := ctlDial()
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()
	if abortable {
		pendMu.Lock()
		pendConn = c
		pendMu.Unlock()
		defer func() {
			pendMu.Lock()
			if pendConn == c {
				pendConn = nil
			}
			pendMu.Unlock()
		}()
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	b, _ := json.Marshal(req)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return nil, nil, err
	}
	var data []byte
	var fds []int
	buf := make([]byte, 64<<10)
	oob := make([]byte, syscall.CmsgSpace(4*8))
	for {
		n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
		data = append(data, buf[:n]...)
		if oobn > 0 {
			if msgs, e := syscall.ParseSocketControlMessage(oob[:oobn]); e == nil {
				for i := range msgs {
					if f, e := syscall.ParseUnixRights(&msgs[i]); e == nil {
						fds = append(fds, f...)
					}
				}
			}
		}
		if bytes.IndexByte(data, '\n') >= 0 {
			break
		}
		if err != nil || n == 0 {
			if len(data) == 0 {
				if err == nil {
					err = errors.New("пустой ответ")
				}
				closeFDs(fds)
				return nil, nil, err
			}
			break
		}
	}
	line := data
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	var resp M
	if err := json.Unmarshal(line, &resp); err != nil {
		closeFDs(fds)
		return nil, nil, err
	}
	if ok, _ := resp["ok"].(bool); !ok {
		closeFDs(fds)
		msg, _ := resp["error"].(string)
		if msg == "" {
			msg = "ошибка приложения"
		}
		return resp, nil, errors.New(msg)
	}
	return resp, fds, nil
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}

var (
	dnsMu   sync.Mutex
	dnsList []string
	dnsRR   atomic.Uint32
)

var fallbackDNS = []string{"77.88.8.8", "1.1.1.1", "8.8.8.8"}

func setSysDNS(list []string) {
	var out []string
	for _, s := range list {
		s = strings.Trim(strings.TrimSpace(s), "[]")
		if i := strings.IndexByte(s, '%'); i >= 0 {
			continue
		}
		if ip := net.ParseIP(s); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			out = append(out, ip.String())
		}
	}
	v4 := out[:0:0]
	var v6 []string
	for _, s := range out {
		if strings.Contains(s, ":") {
			v6 = append(v6, s)
		} else {
			v4 = append(v4, s)
		}
	}
	dnsMu.Lock()
	dnsList = append(v4, v6...)
	dnsMu.Unlock()
}

func sysDNS() []string {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	out := append([]string{}, dnsList...)
	for _, f := range fallbackDNS {
		dup := false
		for _, s := range out {
			dup = dup || s == f
		}
		if !dup {
			out = append(out, f)
		}
	}
	return out
}

func refreshNetInfo() {
	r, _, err := ctlCall(M{"cmd": "netinfo"}, 3*time.Second)
	if err != nil {
		return
	}
	if l, ok := r["dns"].([]any); ok {
		var s []string
		for _, v := range l {
			if x, ok := v.(string); ok {
				s = append(s, x)
			}
		}
		setSysDNS(s)
	}
}

func setupResolver() {
	if e := os.Getenv("VOLFRAM_DNS"); e != "" {
		setSysDNS(strings.Split(e, ","))
	}
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		list := sysDNS()
		d := net.Dialer{Timeout: 4 * time.Second}
		start := int(dnsRR.Add(1))
		var last error
		for i := range list {
			s := list[(start+i)%len(list)]
			c, err := d.DialContext(ctx, network, net.JoinHostPort(s, "53"))
			if err == nil {
				return c, nil
			}
			last = err
		}
		return nil, last
	}}
}

var netTimer *time.Timer
var netMu sync.Mutex

func netChanged(a *App) {
	netMu.Lock()
	defer netMu.Unlock()
	if netTimer != nil {
		netTimer.Stop()
	}
	netTimer = time.AfterFunc(2*time.Second, func() {
		used, _ := usedLocalDNS.Load().(string)
		if a.engine.Status().State != "connected" || used == "" || used == sysDNS()[0] {
			return
		}
		a.Log("app", "info", "Сеть сменилась — переподключение")
		if err := a.Connect(); err != nil {
			a.Log("app", "warn", "Переподключение: "+err.Error())
		}
	})
}

func ctlEvents(a *App) {
	var c *net.UnixConn
	var err error
	for i := 0; i < 50; i++ {
		if c, err = ctlDial(); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		a.Log("app", "warn", "Нет канала событий: "+err.Error())
		return
	}
	_, _ = c.Write([]byte(`{"cmd":"events"}` + "\n"))
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var ev struct {
			Event string   `json:"event"`
			DNS   []string `json:"dns"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		switch ev.Event {
		case "stop":
			go a.engine.Disconnect()
		case "start", "toggle":
			st := a.engine.Status().State
			if ev.Event == "toggle" && (st == "connected" || st == "connecting") {
				go a.engine.Disconnect()
				continue
			}
			if st == "connected" || st == "connecting" {
				continue
			}
			go func() {
				if err := a.Connect(); err != nil {
					a.hub.Send("toast", M{"kind": "error", "text": err.Error()})
					_, _, _ = ctlCall(M{"cmd": "error", "text": err.Error()}, 3*time.Second)
				}
			}()
		case "dns":
			setSysDNS(ev.DNS)
			netChanged(a)
		}
	}
	a.Shutdown()
	os.Exit(0)
}
