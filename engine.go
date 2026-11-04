package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
var levelRe = regexp.MustCompile(`(?i)\b(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|PANIC)\b`)

type LogEntry struct {
	T     int64  `json:"t"`
	Src   string `json:"src"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

type Status struct {
	State    string `json:"state"`
	ServerID string `json:"serverId"`
	Since    int64  `json:"since"`
	Error    string `json:"error"`
	Mode     string `json:"mode"`
	Core     string `json:"core"`
	Port     int    `json:"port"`
}

type Engine struct {
	app       *App
	mu        sync.Mutex
	smu       sync.RWMutex
	status    Status
	sb, xr    *exec.Cmd
	t2s       *exec.Cmd
	vpnOn     bool
	rp        RunPorts
	rpCopy    RunPorts
	cancel    context.CancelFunc
	proxySet  string
	heldProxy string
	wantStop  bool
	exitCh    chan struct{}
	upTotal   int64
	downTotal int64
	testing   sync.Mutex
	gen       atomic.Uint64
	crashes   []time.Time
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func portFree(port int) bool {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

func (e *Engine) Status() Status {
	e.smu.RLock()
	defer e.smu.RUnlock()
	return e.status
}

func (e *Engine) setStatus(s Status) {
	e.smu.Lock()
	e.status = s
	e.smu.Unlock()
	e.app.hub.Send("status", s)
	if h := e.app.hooks.Load(); h != nil && h.status != nil {
		h.status(s)
	}
}

func (e *Engine) logPipe(r io.Reader, src string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(ansiRe.ReplaceAllString(sc.Text(), ""))
		if line == "" {
			continue
		}
		lv := "info"
		if m := levelRe.FindString(line); m != "" {
			lv = strings.ToLower(m)
			if lv == "warning" {
				lv = "warn"
			}
		}
		if m := sbPrefixRe.FindStringSubmatchIndex(line); m != nil {
			line = line[m[1]:]
		} else if m := xrPrefixRe.FindStringSubmatchIndex(line); m != nil {
			line = line[m[1]:]
		}
		e.app.Log(src, lv, line)
	}
}

var sbPrefixRe = regexp.MustCompile(`^[+-]\d{4} \d{4}-\d\d-\d\d \d\d:\d\d:\d\d (TRACE|DEBUG|INFO|WARN|ERROR|FATAL|PANIC) `)
var xrPrefixRe = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d(\.\d+)? (\[(Debug|Info|Warning|Error)\] )?`)

func (e *Engine) startProc(bin string, args []string, src string, stdin []byte, extra ...*os.File) (*exec.Cmd, error) {
	beforeCoreStart(filepath.Dir(bin))
	cmd := exec.Command(bin, args...)
	cmd.Dir = filepath.Dir(bin)
	cmd.ExtraFiles = extra
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	hideCmd(cmd)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	attachJob(cmd)
	go e.logPipe(stdout, src)
	go e.logPipe(stderr, src)
	return cmd, nil
}

func waitTCP(addr string, d time.Duration, alive func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
			c.Close()
			return true
		}
		if alive != nil && !alive() {
			return false
		}
		time.Sleep(120 * time.Millisecond)
	}
	return false
}

func procAlive(cmd *exec.Cmd, done <-chan struct{}) func() bool {
	return func() bool {
		select {
		case <-done:
			return false
		default:
			return true
		}
	}
}

var ErrNeedAdmin = errors.New("need_admin")
var ErrCancelled = errors.New("подключение отменено")

func (e *Engine) Connect(sv *Server, s Settings) error {
	e.gen.Add(1)
	e.disconnect(isAndroid && s.Mode == "tun", !isAndroid && s.Mode == "proxy")
	e.mu.Lock()
	defer e.mu.Unlock()
	defer func() {
		if e.Status().State != "connected" {
			e.releaseHeld()
		}
	}()
	e.wantStop = false
	platformPreConnect()
	if s.Mode == "tun" && !isAdmin() {
		return ErrNeedAdmin
	}
	n, err := ParseLink(sv.Link)
	if err != nil {
		return err
	}
	if isAndroid && n.Proto == "naive" {
		return errors.New("NaïveProxy пока не поддерживается в Android-версии — выберите другой сервер")
	}
	e.setStatus(Status{State: "connecting", ServerID: sv.ID, Mode: s.Mode, Core: n.Core(), Port: s.MixedPort})
	_ = os.MkdirAll(e.app.runDir, 0o700)
	fail := func(err error) error {
		cancelled := e.wantStop
		e.killLocked()
		e.extDown(true)
		if cancelled {
			err = ErrCancelled
		}
		msg := err.Error()
		if cancelled {
			msg = ""
		}
		e.setStatus(Status{State: "idle", ServerID: sv.ID, Error: msg, Mode: s.Mode})
		return err
	}
	if err := e.app.WaitCores(); err != nil {
		return fail(fmt.Errorf("ядро не готово: %v", err))
	}
	e.rp = RunPorts{Mixed: s.MixedPort, Clash: freePort(), Xray: freePort(), Secret: randHex(16),
		XUser: "x" + randHex(4), XPass: randHex(16)}
	if isAndroid && s.Mode == "tun" {
		e.rp.Mixed = freePort()
		e.rp.User, e.rp.Pass = "u"+randHex(4), randHex(16)
	} else {
		if !portFree(s.MixedPort) {
			return fail(fmt.Errorf("порт %d занят другой программой — измените его в настройках", s.MixedPort))
		}
		if s.AllowLAN && !isAndroid && !portFree(s.MixedPort+1) {
			return fail(fmt.Errorf("порт %d для устройств в сети занят другой программой", s.MixedPort+1))
		}
	}
	e.wantStop = false
	runDir := e.app.runDir
	viaX := n.NeedsXray()

	sbDone := make(chan struct{})
	xrDone := make(chan struct{})
	if viaX {
		if r := n.XrayRefusal(); r != "" {
			return fail(errors.New(r))
		}
		if n.Insecure {
			e.app.Log("app", "warn", "Xray-core не поддерживает allowInsecure — сертификат сервера будет проверяться")
		}
		xc, err := BuildXrayAuth(n, e.rp, s.LogLevel)
		if err != nil {
			return fail(err)
		}
		xb, _ := json.Marshal(xc)
		e.app.Log("app", "info", "Запуск Xray-core для "+strings.Join(n.Tags(), "/"))
		cmd, err := e.startProc(e.app.xrayPath(), []string{"run", "-c", "stdin:"}, "xray", xb)
		if err != nil {
			return fail(fmt.Errorf("не удалось запустить Xray: %v", err))
		}
		e.xr = cmd
		go func() { _ = cmd.Wait(); close(xrDone) }()
		if !waitTCP(fmt.Sprintf("127.0.0.1:%d", e.rp.Xray), 6*time.Second, procAlive(cmd, xrDone)) {
			return fail(errors.New("Xray не запустился — проверьте журнал"))
		}
	} else {
		close(xrDone)
	}

	cfg, err := BuildSingbox(n, &s, e.rp, e.app.rulesDir, viaX)
	if err != nil {
		return fail(err)
	}
	if insecureTLS(cfg) {
		e.app.Log("app", "warn", "У сервера отключена проверка TLS-сертификата (allowInsecure) — соединение могут перехватить. Попросите у провайдера ссылку с нормальным сертификатом")
	}
	cb, _ := json.Marshal(cfg)
	e.app.Log("app", "info", fmt.Sprintf("Подключение к %s (%s, режим %s)", sv.Name, strings.ToUpper(n.Proto), strings.ToUpper(s.Mode)))
	cmd, err := e.startProc(e.app.singboxPath(), []string{"run", "-c", "stdin", "-D", runDir, "--disable-color"}, "sing-box", cb)
	if err != nil {
		return fail(fmt.Errorf("не удалось запустить sing-box: %v", err))
	}
	e.sb = cmd
	go func() { _ = cmd.Wait(); close(sbDone) }()
	if !waitTCP(fmt.Sprintf("127.0.0.1:%d", e.rp.Clash), 12*time.Second, procAlive(cmd, sbDone)) {
		return fail(errors.New("sing-box не запустился: " + e.app.lastError("sing-box")))
	}
	if !waitTCP(fmt.Sprintf("127.0.0.1:%d", e.rp.Mixed), 3*time.Second, procAlive(cmd, sbDone)) {
		return fail(errors.New("локальный порт не открылся"))
	}
	var extDone chan struct{}
	if s.Mode == "tun" && isAndroid {
		d, err := e.extUp(sv, s)
		if err != nil {
			return fail(err)
		}
		extDone = d
	}
	if s.Mode == "proxy" {
		addr := fmt.Sprintf("127.0.0.1:%d", s.MixedPort)
		if err := setSystemProxy(addr); err != nil {
			e.app.Log("app", "warn", "Не удалось включить системный прокси: "+err.Error())
			if e.heldProxy == addr {
				e.proxySet = addr
				e.heldProxy = ""
			} else {
				e.releaseHeld()
			}
		} else {
			e.proxySet = addr
			e.heldProxy = ""
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.exitCh = make(chan struct{})
	e.upTotal, e.downTotal = 0, 0
	e.smu.Lock()
	e.rpCopy = e.rp
	e.smu.Unlock()
	e.setStatus(Status{State: "connected", ServerID: sv.ID, Since: time.Now().UnixMilli(), Mode: s.Mode, Core: n.Core(), Port: e.rp.Mixed})
	e.app.Log("app", "info", "Подключено ✓")
	go e.statsLoop(ctx, e.rp)
	go e.selfCheck(ctx, e.rp, s)
	go e.watch(ctx, sbDone, xrDone, extDone, viaX, sv)
	go e.app.FetchIP(e.rp.Mixed)
	return nil
}

func (e *Engine) watch(ctx context.Context, sbDone, xrDone, extDone chan struct{}, hasXray bool, sv *Server) {
	var which string
	if !hasXray {
		xrDone = nil
	}
	select {
	case <-ctx.Done():
		return
	case <-sbDone:
		which = "sing-box"
	case <-xrDone:
		which = "xray"
	case <-extDone:
		which = "tun2socks"
	}
	e.mu.Lock()
	if e.wantStop {
		e.mu.Unlock()
		return
	}
	msg := which + " неожиданно завершился"
	if le := e.app.lastFatal(which); le != "" {
		msg += ": " + le
	}
	e.app.Log("app", "error", msg)
	mode := e.status.Mode
	keepVPN := isAndroid && e.vpnOn
	now := time.Now()
	var recent []time.Time
	for _, t := range e.crashes {
		if now.Sub(t) < 2*time.Minute {
			recent = append(recent, t)
		}
	}
	e.crashes = append(recent, now)
	retry := len(e.crashes) <= 3
	if retry {
		e.holdProxy()
	}
	e.killLocked()
	e.extDown(!keepVPN)
	if retry {
		e.setStatus(Status{State: "connecting", ServerID: sv.ID, Mode: mode})
	} else {
		e.extDown(true)
		e.releaseHeld()
		e.setStatus(Status{State: "idle", ServerID: sv.ID, Error: msg, Mode: mode})
	}
	g := e.gen.Load()
	e.mu.Unlock()
	if !retry {
		e.app.hub.Send("toast", M{"kind": "error", "text": "Соединение разорвано: ядро " + which + " остановилось"})
		return
	}
	note := ""
	if keepVPN {
		note = " Пока связь не восстановлена, интернет заблокирован — без утечек мимо VPN."
	}
	e.app.Log("app", "warn", "Восстанавливаю соединение…"+note)
	time.Sleep(1500 * time.Millisecond)
	if e.gen.Load() != g {
		return
	}
	if err := e.app.Connect(); err != nil && err != ErrCancelled {
		e.mu.Lock()
		if e.Status().State != "connected" {
			e.releaseHeld()
		}
		e.mu.Unlock()
		e.app.Log("app", "error", "Восстановить соединение не удалось: "+err.Error())
		e.app.hub.Send("toast", M{"kind": "error", "text": "Соединение разорвано и не восстановилось: " + err.Error()})
	}
}

func (e *Engine) killLocked() {
	e.wantStop = true
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	if e.proxySet != "" {
		_ = clearSystemProxy(e.proxySet)
		e.proxySet = ""
	}
	e.extDown(false)
	for _, c := range []*exec.Cmd{e.sb, e.xr} {
		if c != nil && c.Process != nil {
			_ = c.Process.Kill()
		}
	}
	e.sb, e.xr = nil, nil
}

func insecureTLS(cfg M) bool {
	for _, k := range []string{"outbounds", "endpoints"} {
		list, _ := cfg[k].([]M)
		for _, o := range list {
			if t, ok := o["tls"].(M); ok && t["insecure"] == true {
				return true
			}
		}
	}
	return false
}

func (e *Engine) holdProxy() {
	if e.proxySet != "" {
		e.heldProxy, e.proxySet = e.proxySet, ""
	}
}

func (e *Engine) releaseHeld() {
	if e.heldProxy != "" {
		_ = clearSystemProxy(e.heldProxy)
		e.heldProxy = ""
	}
}

func (e *Engine) Disconnect() { e.disconnect(false, false) }

func (e *Engine) disconnect(keepVPN, keepProxy bool) {
	e.gen.Add(1)
	e.wantStop = true
	platformAbort()
	e.mu.Lock()
	defer e.mu.Unlock()
	if keepProxy {
		e.holdProxy()
	} else {
		defer e.releaseHeld()
	}
	cur := e.Status()
	if cur.State == "idle" || cur.State == "" {
		e.killLocked()
		e.extDown(!keepVPN)
		return
	}
	e.setStatus(Status{State: "stopping", ServerID: cur.ServerID})
	e.killLocked()
	e.extDown(!keepVPN)
	time.Sleep(150 * time.Millisecond)
	e.setStatus(Status{State: "idle", ServerID: cur.ServerID})
	e.app.Log("app", "info", "Отключено")
	e.app.hub.Send("stats", M{"up": 0, "down": 0, "upTotal": e.upTotal, "downTotal": e.downTotal, "conns": 0})
}

func (e *Engine) clashReq(rp RunPorts, method, path string, timeout time.Duration) (*http.Response, error) {
	req, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", rp.Clash, path), nil)
	req.Header.Set("Authorization", "Bearer "+rp.Secret)
	c := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}}
	return c.Do(req)
}

type clashConns struct {
	DownloadTotal int64 `json:"downloadTotal"`
	UploadTotal   int64 `json:"uploadTotal"`
	Connections   []struct {
		ID          string   `json:"id"`
		Upload      int64    `json:"upload"`
		Download    int64    `json:"download"`
		Start       string   `json:"start"`
		Chains      []string `json:"chains"`
		Rule        string   `json:"rule"`
		RulePayload string   `json:"rulePayload"`
		Metadata    struct {
			Network     string `json:"network"`
			Type        string `json:"type"`
			SourceIP    string `json:"sourceIP"`
			DestIP      string `json:"destinationIP"`
			DestPort    string `json:"destinationPort"`
			Host        string `json:"host"`
			ProcessPath string `json:"processPath"`
		} `json:"metadata"`
	} `json:"connections"`
}

func (e *Engine) statsLoop(ctx context.Context, rp RunPorts) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var lastUp, lastDown int64 = -1, -1
	lastT := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		resp, err := e.clashReq(rp, "GET", "/connections", 2*time.Second)
		if err != nil {
			continue
		}
		var cc clashConns
		_ = json.NewDecoder(resp.Body).Decode(&cc)
		resp.Body.Close()
		now := time.Now()
		dt := now.Sub(lastT).Seconds()
		if dt <= 0 {
			dt = 1
		}
		var up, down float64
		if lastUp >= 0 {
			up = float64(cc.UploadTotal-lastUp) / dt
			down = float64(cc.DownloadTotal-lastDown) / dt
			if up < 0 {
				up = 0
			}
			if down < 0 {
				down = 0
			}
		}
		lastUp, lastDown, lastT = cc.UploadTotal, cc.DownloadTotal, now
		e.smu.Lock()
		e.upTotal, e.downTotal = cc.UploadTotal, cc.DownloadTotal
		e.smu.Unlock()
		e.app.hub.Send("stats", M{"up": int64(up), "down": int64(down), "upTotal": cc.UploadTotal, "downTotal": cc.DownloadTotal, "conns": len(cc.Connections)})
	}
}

func (e *Engine) Connections() (any, error) {
	e.smu.RLock()
	st := e.status.State
	e.smu.RUnlock()
	rp := e.rpSnapshot()
	if st != "connected" {
		return M{"connections": []any{}}, nil
	}
	resp, err := e.clashReq(rp, "GET", "/connections", 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var cc clashConns
	if err := json.NewDecoder(resp.Body).Decode(&cc); err != nil {
		return nil, err
	}
	return cc, nil
}

func (e *Engine) CloseConnection(id string) error {
	e.smu.RLock()
	st := e.status.State
	e.smu.RUnlock()
	rp := e.rpSnapshot()
	if st != "connected" {
		return nil
	}
	path := "/connections"
	if id != "" {
		path += "/" + url.PathEscape(id)
	}
	resp, err := e.clashReq(rp, "DELETE", path, 3*time.Second)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func tcpPing(host string, port int) int {
	best := -1
	for i := 0; i < 2; i++ {
		t0 := time.Now()
		c, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 3*time.Second)
		if err != nil {
			continue
		}
		c.Close()
		ms := int(time.Since(t0).Milliseconds())
		if ms < 1 {
			ms = 1
		}
		if best < 0 || ms < best {
			best = ms
		}
	}
	return best
}

var outIdxRe = regexp.MustCompile(`(outbound|endpoint)\[(\d+)\]`)

func udpOnly(n *Node) bool {
	switch n.Proto {
	case "hysteria", "hysteria2", "tuic", "wireguard":
		return true
	}
	switch n.Net {
	case "kcp", "mkcp", "quic":
		return true
	}
	return false
}

func proxyGet(port int, user, pass, testURL string, timeout time.Duration) (int, error) {
	pu := &url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", port)}
	if user != "" {
		pu.User = url.UserPassword(user, pass)
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyURL(pu),
		DisableKeepAlives:     true,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return -1, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	t0 := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		return -1, err
	}
	ms := int(time.Since(t0).Milliseconds())
	resp.Body.Close()
	if ms < 1 {
		ms = 1
	}
	return ms, nil
}

func getDelay(port int, user, pass, testURL string) int {
	best := -1
	for i := 0; i < 2; i++ {
		ms, err := proxyGet(port, user, pass, testURL, 6*time.Second)
		if err == nil && (best < 0 || ms < best) {
			best = ms
		}
	}
	return best
}

type pingItem struct {
	sv *Server
	n  *Node
}

func pingFallback(it pingItem) int {
	if udpOnly(it.n) {
		return -1
	}
	return tcpPing(it.n.Host, it.n.Port)
}

func (e *Engine) TestDelays(servers []*Server, s Settings) {
	if !e.testing.TryLock() {
		e.app.hub.Send("toast", M{"kind": "info", "text": "Тест уже выполняется"})
		return
	}
	defer e.testing.Unlock()
	e.app.hub.Send("testing", M{"active": true, "ids": serverIDs(servers)})
	defer e.app.hub.Send("testing", M{"active": false})
	results := map[string]int{}
	var rmu sync.Mutex
	report := func(id string, d int) {
		rmu.Lock()
		results[id] = d
		rmu.Unlock()
		e.app.hub.Send("delay", M{"id": id, "delay": d})
	}
	mode := s.PingMode
	if mode != "tcp" && mode != "get" {
		mode = defaultPingMode
	}
	if st := e.Status(); mode == "tcp" && !isAndroid && st.State == "connected" && st.Mode == "tun" {
		mode = "get"
	}
	if s.TestURL == "" {
		s.TestURL = "https://www.gstatic.com/generate_204"
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	var sbItems, xrItems []pingItem
	for _, sv := range servers {
		n, err := ParseLink(sv.Link)
		if err != nil {
			report(sv.ID, -1)
			continue
		}
		it := pingItem{sv, n}
		switch {
		case mode == "tcp" && !udpOnly(n):
			parRun(&wg, sem, func() { report(sv.ID, tcpPing(n.Host, n.Port)) })
		case n.NeedsXray():
			if _, err := xrayOutbound(n, "p"); err != nil || n.XrayRefusal() != "" {
				report(sv.ID, -1)
			} else {
				xrItems = append(xrItems, it)
			}
		default:
			if _, _, err := SingboxOutbound(n, "t"); err != nil {
				report(sv.ID, -1)
			} else {
				sbItems = append(sbItems, it)
			}
		}
	}
	if len(sbItems)+len(xrItems) > 0 {
		if err := e.app.WaitCores(); err != nil {
			for _, it := range append(sbItems, xrItems...) {
				parRun(&wg, sem, func() { report(it.sv.ID, pingFallback(it)) })
			}
		} else {
			wg.Add(1)
			go func() { defer wg.Done(); e.getTest(sbItems, xrItems, s, report, sem) }()
		}
	}
	wg.Wait()
	e.app.store.mu.Lock()
	for id, d := range results {
		if sv := e.app.store.find(id); sv != nil {
			sv.Delay = d
		}
	}
	_ = e.app.store.Save()
	e.app.store.mu.Unlock()
}

func parRun(wg *sync.WaitGroup, sem chan struct{}, f func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()
		f()
	}()
}

func (e *Engine) startXrayTester(items []pingItem) (stop func(), ports []int, user, pass string, err error) {
	nodes := make([]*Node, len(items))
	ports = make([]int, len(items))
	for i, it := range items {
		nodes[i], ports[i] = it.n, freePort()
	}
	user, pass = "t"+randHex(4), randHex(12)
	cfg, _ := json.Marshal(BuildXrayTester(nodes, ports, user, pass))
	beforeCoreStart(filepath.Dir(e.app.xrayPath()))
	cmd := exec.Command(e.app.xrayPath(), "run", "-c", "stdin:")
	cmd.Dir = filepath.Dir(e.app.xrayPath())
	cmd.Stdin = bytes.NewReader(cfg)
	hideCmd(cmd)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return nil, nil, "", "", err
	}
	attachJob(cmd)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	stop = func() { _ = cmd.Process.Kill(); <-done }
	if !waitTCP(fmt.Sprintf("127.0.0.1:%d", ports[len(ports)-1]), 6*time.Second, procAlive(cmd, done)) {
		stop()
		return nil, nil, "", "", errors.New(lastLines(out.String(), 3))
	}
	return stop, ports, user, pass, nil
}

func (e *Engine) clashDelay(rp RunPorts, tag, testURL string, timeout time.Duration) (int, int, string) {
	path := fmt.Sprintf("/proxies/%s/delay?timeout=%d&url=%s", url.PathEscape(tag), timeout.Milliseconds(), url.QueryEscape(testURL))
	resp, err := e.clashReq(rp, "GET", path, timeout+3*time.Second)
	if err != nil {
		return -1, 0, err.Error()
	}
	defer resp.Body.Close()
	var r struct {
		Delay   int    `json:"delay"`
		Message string `json:"message"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&r)
	if resp.StatusCode == 200 && r.Delay > 0 {
		return r.Delay, 200, ""
	}
	switch {
	case r.Message == "An error occurred in the delay test":
		r.Message = "ошибка соединения"
	case strings.Contains(strings.ToLower(r.Message), "timeout"):
		r.Message = fmt.Sprintf("нет ответа за %d с", int(timeout.Seconds()))
	case r.Message == "":
		r.Message = resp.Status
	}
	return -1, resp.StatusCode, r.Message
}

func (e *Engine) getTest(sbItems, xrItems []pingItem, s Settings, report func(string, int), sem chan struct{}) {
	var wg sync.WaitGroup
	var stopX func()
	defer func() {
		wg.Wait()
		if stopX != nil {
			stopX()
		}
	}()
	items := append([]pingItem{}, sbItems...)
	nodes := make([]*Node, 0, len(sbItems)+len(xrItems))
	for _, it := range sbItems {
		nodes = append(nodes, it.n)
	}
	type xref struct {
		port       int
		user, pass string
	}
	viaXray := map[int]xref{}
	if len(xrItems) > 0 {
		stop, ports, u, p, err := e.startXrayTester(xrItems)
		if err != nil {
			e.app.Log("app", "warn", "Тестер Xray не запустился, используется TCP-пинг: "+err.Error())
			for _, it := range xrItems {
				parRun(&wg, sem, func() { report(it.sv.ID, pingFallback(it)) })
			}
		} else {
			stopX = stop
			for i, it := range xrItems {
				viaXray[len(items)] = xref{ports[i], u, p}
				items = append(items, it)
				nodes = append(nodes, &Node{Proto: "socks", Host: "127.0.0.1", Port: ports[i], User: u, Password: p, Name: it.n.Name})
			}
		}
	}
	if len(items) == 0 {
		return
	}
	excluded := map[int]bool{}
	for attempt := 0; attempt < 8; attempt++ {
		var idx []int
		var tags []string
		var ns []*Node
		var ports []int
		for i := range items {
			if !excluded[i] {
				idx = append(idx, i)
				tags = append(tags, fmt.Sprintf("t%d", i))
				ns = append(ns, nodes[i])
				ports = append(ports, freePort())
			}
		}
		if len(idx) == 0 {
			return
		}
		rp := RunPorts{Clash: freePort(), Secret: randHex(16), User: "t" + randHex(4), Pass: randHex(12)}
		cfg, pos := BuildTester(tags, ns, &s, rp, ports)
		cb, _ := json.Marshal(cfg)
		_ = os.MkdirAll(e.app.runDir, 0o700)
		beforeCoreStart(filepath.Dir(e.app.singboxPath()))
		cmd := exec.Command(e.app.singboxPath(), "run", "-c", "stdin", "-D", e.app.runDir, "--disable-color")
		cmd.Dir = filepath.Dir(e.app.singboxPath())
		cmd.Stdin = bytes.NewReader(cb)
		hideCmd(cmd)
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		startErr := cmd.Start()
		var done chan struct{}
		alive := func() bool { return false }
		if startErr == nil {
			attachJob(cmd)
			done = make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			alive = procAlive(cmd, done)
		}
		if startErr != nil || !waitTCP(fmt.Sprintf("127.0.0.1:%d", rp.Clash), 8*time.Second, alive) {
			msg := ""
			if startErr != nil {
				msg = startErr.Error()
			} else {
				_ = cmd.Process.Kill()
				<-done
				msg = strings.TrimSpace(ansiRe.ReplaceAllString(out.String(), ""))
			}
			if m := outIdxRe.FindStringSubmatch(msg); m != nil {
				if tag, ok := pos[m[1]+"["+m[2]+"]"]; ok {
					var k int
					fmt.Sscanf(tag, "t%d", &k)
					excluded[k] = true
					report(items[k].sv.ID, -1)
					e.app.Log("app", "warn", "Сервер «"+items[k].sv.Name+"» исключён из теста: "+lastLines(msg, 3))
					continue
				}
			}
			e.app.Log("app", "warn", "Тестер не запустился, используется запасной способ: "+lastLines(msg, 3))
			for _, i := range idx {
				it := items[i]
				if x, ok := viaXray[i]; ok {
					parRun(&wg, sem, func() { report(it.sv.ID, getDelay(x.port, x.user, x.pass, s.TestURL)) })
				} else {
					parRun(&wg, sem, func() { report(it.sv.ID, pingFallback(it)) })
				}
			}
			return
		}
		waitTCP(fmt.Sprintf("127.0.0.1:%d", ports[len(ports)-1]), 3*time.Second, alive)
		var iw sync.WaitGroup
		var fmu sync.Mutex
		failed, why := 0, ""
		for k, i := range idx {
			it, tag, port := items[i], tags[k], ports[k]
			parRun(&iw, sem, func() {
				best, reason := -1, ""
				for try := 0; try < 2; try++ {
					d, code, r := e.clashDelay(rp, tag, s.TestURL, 7*time.Second)
					if code == http.StatusNotFound {
						d, reason = getDelay(port, rp.User, rp.Pass, s.TestURL), "нет ответа"
					} else if r != "" {
						reason = r
					}
					if d > 0 && (best < 0 || d < best) {
						best = d
					}
					if code == http.StatusNotFound || (best < 0 && try == 0 && strings.HasPrefix(reason, "нет ответа")) {
						break
					}
				}
				if best < 0 {
					fmu.Lock()
					failed++
					if why == "" {
						why = reason
					}
					fmu.Unlock()
				}
				report(it.sv.ID, best)
			})
		}
		iw.Wait()
		_ = cmd.Process.Kill()
		<-done
		if failed > 0 {
			msg := fmt.Sprintf("Проверка задержки: без ответа %d из %d (%s)", failed, len(idx), why)
			if failed == len(idx) {
				if tail := lastLines(ansiRe.ReplaceAllString(out.String(), ""), 2); tail != "" {
					msg += " — " + tail
				}
			}
			e.app.Log("app", "warn", msg)
		}
		return
	}
	for i := range items {
		if !excluded[i] {
			it := items[i]
			parRun(&wg, sem, func() { report(it.sv.ID, pingFallback(it)) })
		}
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.TrimSpace(strings.Join(lines, " | "))
}

func (e *Engine) selfCheck(ctx context.Context, rp RunPorts, s Settings) {
	testURL := s.TestURL
	select {
	case <-ctx.Done():
		return
	case <-time.After(800 * time.Millisecond):
	}
	if testURL == "" {
		testURL = "https://www.gstatic.com/generate_204"
	}
	t0 := time.Now().UnixMilli()
	last := ""
	for try := 0; try < 2; try++ {
		resp, err := e.clashReq(rp, "GET", "/proxies/proxy/delay?timeout=8000&url="+url.QueryEscape(testURL), 10*time.Second)
		if ctx.Err() != nil {
			if resp != nil {
				resp.Body.Close()
			}
			return
		}
		if err != nil {
			last = err.Error()
			continue
		}
		var r struct {
			Delay   int    `json:"delay"`
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&r)
		resp.Body.Close()
		if resp.StatusCode == 200 && r.Delay > 0 {
			e.app.Log("app", "info", fmt.Sprintf("Проверка связи через сервер: %d мс ✓", r.Delay))
			return
		}
		last = r.Message
		if last == "An error occurred in the delay test" {
			last = "ошибка соединения"
		}
		if last == "" {
			last = resp.Status
		}
	}
	if strings.Contains(last, "deadline") || strings.Contains(last, "timeout") || strings.Contains(last, "Timeout") {
		last = "нет ответа за 8 с"
	}
	if s.Routing != "blocked" && rp.Mixed > 0 {
		_, gerr := proxyGet(rp.Mixed, rp.User, rp.Pass, testURL, 8*time.Second)
		if ctx.Err() != nil {
			return
		}
		if gerr == nil {
			e.app.Log("app", "info", "Проверка связи через сервер: ответ получен со второй попытки")
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	if d := e.app.errorSince(t0, "sing-box", "xray"); d != "" {
		if i := strings.Index(d, "] "); i >= 0 && strings.HasPrefix(d, "[") {
			d = d[i+2:]
		}
		last += " — " + d
	}
	e.app.Log("app", "warn", "Проверка связи через сервер не прошла: "+last)
	e.app.hub.Send("toast", M{"kind": "error", "text": "Сервер не отвечает — интернет через VPN может не работать. Подробности в журнале"})
}

func serverIDs(list []*Server) []string {
	ids := make([]string, 0, len(list))
	for _, s := range list {
		ids = append(ids, s.ID)
	}
	return ids
}

func (e *Engine) rpSnapshot() RunPorts {
	e.smu.RLock()
	defer e.smu.RUnlock()
	return e.rpCopy
}
