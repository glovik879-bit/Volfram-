package main

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const AppVersion = "1.0.8"

//go:embed ui
var uiFS embed.FS

type Hub struct {
	mu      sync.Mutex
	clients map[chan []byte]bool
}

func (h *Hub) Send(typ string, data any) {
	b, err := json.Marshal(M{"type": typ, "data": data})
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case c <- b:
		default:
		}
	}
}

func (h *Hub) add() chan []byte {
	c := make(chan []byte, 512)
	h.mu.Lock()
	h.clients[c] = true
	h.mu.Unlock()
	return c
}

func (h *Hub) remove(c chan []byte) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

type App struct {
	store          *Store
	engine         *Engine
	hub            *Hub
	token          string
	assetKey       string
	dataDir        string
	coreDir        string
	rulesDir       string
	runDir         string
	coresOnce      sync.Once
	coresErr       error
	coresDone      chan struct{}
	logMu          sync.Mutex
	logs           []LogEntry
	ipMu           sync.Mutex
	ipGen          uint64
	ip             M
	versions       M
	onQuit         func()
	onRestartAdmin func() error
	hooks          atomic.Pointer[appHooks]
}

type appHooks struct {
	status    func(Status)
	needAdmin func()
}

func (a *App) needAdmin() {
	a.hub.Send("needAdmin", M{})
	if h := a.hooks.Load(); h != nil && h.needAdmin != nil {
		h.needAdmin()
	}
}

func (a *App) selectServer(id string) bool {
	a.store.mu.Lock()
	ok := a.store.find(id) != nil
	if ok && a.store.Selected != id {
		a.store.Selected = id
		_ = a.store.Save()
	}
	a.store.mu.Unlock()
	if ok {
		a.pushServers()
	}
	return ok
}

func NewApp(cfgDir, dataDir string) *App {
	a := &App{
		store:     LoadStore(filepath.Join(cfgDir, "config.json")),
		hub:       &Hub{clients: map[chan []byte]bool{}},
		token:     randHex(16),
		assetKey:  randHex(16),
		dataDir:   dataDir,
		coreDir:   filepath.Join(dataDir, "core"),
		rulesDir:  filepath.Join(dataDir, "core", "rules"),
		runDir:    filepath.Join(dataDir, "run"),
		coresDone: make(chan struct{}),
		versions:  M{"app": AppVersion, "singbox": SingboxVersion, "xray": XrayVersion},
	}
	a.engine = &Engine{app: a, status: Status{State: "idle"}}
	return a
}

func (a *App) Log(src, level, msg string) {
	e := LogEntry{T: time.Now().UnixMilli(), Src: src, Level: level, Msg: redact(msg)}
	a.logMu.Lock()
	a.logs = append(a.logs, e)
	if len(a.logs) > 2000 {
		a.logs = a.logs[len(a.logs)-1500:]
	}
	a.logMu.Unlock()
	a.hub.Send("log", e)
}

func (a *App) errorSince(t0 int64, srcs ...string) string {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	for i := len(a.logs) - 1; i >= 0 && a.logs[i].T >= t0; i-- {
		l := a.logs[i]
		if l.Level != "error" && l.Level != "fatal" && l.Level != "warn" {
			continue
		}
		for _, s := range srcs {
			if l.Src == s {
				return l.Msg
			}
		}
	}
	return ""
}

func pluralRu(n int, one, few, many string) string {
	m10, m100 := n%10, n%100
	switch {
	case m10 == 1 && m100 != 11:
		return one
	case m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20):
		return few
	}
	return many
}

func (a *App) lastFatal(src string) string {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	for i := len(a.logs) - 1; i >= 0 && i > len(a.logs)-60; i-- {
		if l := a.logs[i]; l.Src == src && (l.Level == "error" || l.Level == "fatal" || l.Level == "panic") {
			return l.Msg
		}
	}
	return ""
}

func (a *App) lastError(src string) string {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	for i := len(a.logs) - 1; i >= 0 && i > len(a.logs)-60; i-- {
		l := a.logs[i]
		if l.Src == src && (l.Level == "error" || l.Level == "fatal" || l.Level == "panic") {
			m := l.Msg
			if j := strings.Index(m, "FATAL"); j >= 0 {
				m = m[j:]
			}
			return m
		}
	}
	for i := len(a.logs) - 1; i >= 0 && i > len(a.logs)-60; i-- {
		if a.logs[i].Src == src {
			return a.logs[i].Msg
		}
	}
	return "подробности в журнале"
}

func (a *App) PrepareCores() {
	a.coresOnce.Do(func() {
		go func() {
			t0 := time.Now()
			a.coresErr = extractCores(a.coreDir, a.rulesDir)
			if a.coresErr != nil {
				a.Log("app", "error", "Ошибка подготовки ядер: "+a.coresErr.Error())
			} else {
				a.Log("app", "info", fmt.Sprintf("Ядра готовы: sing-box %s, Xray %s (%dms)", SingboxVersion, XrayVersion, time.Since(t0).Milliseconds()))
			}
			close(a.coresDone)
			a.hub.Send("cores", M{"ready": a.coresErr == nil})
		}()
	})
}

func (a *App) WaitCores() error {
	<-a.coresDone
	return a.coresErr
}

func (a *App) coresReady() bool {
	select {
	case <-a.coresDone:
		return a.coresErr == nil
	default:
		return false
	}
}

func (a *App) singboxPath() string { return filepath.Join(a.coreDir, exeName("sing-box")) }
func (a *App) xrayPath() string    { return filepath.Join(a.coreDir, exeName("xray")) }

func (a *App) AddText(text string) (added int, subs int, errs []string) {
	text = strings.TrimSpace(text)
	var subURLs []string
	var links []string
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		low := strings.ToLower(l)
		if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
			subURLs = append(subURLs, l)
		}
	}
	var nodes []*Node
	if len(subURLs) == 0 {
		if t := strings.TrimSpace(text); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") || strings.Contains(t, "proxies:") {
			nodes, _ = ParseSubscriptionBody([]byte(t))
			if len(nodes) == 0 {
				errs = append(errs, "в конфигурации не найдено поддерживаемых серверов")
			}
		} else {
			links = SplitInput(text)
		}
	} else {
		for _, line := range strings.Split(text, "\n") {
			l := strings.TrimSpace(line)
			low := strings.ToLower(l)
			if strings.Contains(l, "://") && !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
				links = append(links, l)
			}
		}
	}
	for _, l := range links {
		n, err := ParseLink(l)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		nodes = append(nodes, n)
	}
	a.store.mu.Lock()
	for _, n := range nodes {
		sv := serverFromNode(n, "")
		if a.store.find(sv.ID) != nil {
			continue
		}
		a.store.Servers = append(a.store.Servers, sv)
		added++
		if a.store.Selected == "" {
			a.store.Selected = sv.ID
		}
	}
	_ = a.store.Save()
	a.store.mu.Unlock()
	for _, u := range subURLs {
		if _, err := a.AddSubscription(u, ""); err != nil {
			errs = append(errs, err.Error())
		} else {
			subs++
		}
	}
	a.pushServers()
	return
}

func (a *App) pushServers() {
	a.store.mu.Lock()
	b, _ := json.Marshal(M{"servers": a.store.Servers, "subs": a.store.Subs, "selected": a.store.Selected})
	a.store.mu.Unlock()
	a.hub.Send("servers", json.RawMessage(b))
}

func (a *App) AddSubscription(u, name string) (*Subscription, error) {
	pu, err := url.Parse(strings.TrimSpace(u))
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
		return nil, errors.New("некорректный адрес подписки")
	}
	a.store.mu.Lock()
	for _, s := range a.store.Subs {
		if s.URL == pu.String() {
			a.store.mu.Unlock()
			return s, a.UpdateSubscription(s.ID)
		}
	}
	sub := &Subscription{ID: randHex(5), URL: pu.String(), Name: cleanText(name, 120)}
	if sub.Name == "" {
		sub.Name = pu.Hostname()
	}
	a.store.Subs = append(a.store.Subs, sub)
	_ = a.store.Save()
	a.store.mu.Unlock()
	return sub, a.UpdateSubscription(sub.ID)
}

func decodeHeaderText(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "base64:") {
		if b, err := b64decode(strings.TrimPrefix(v, "base64:")); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return v
}

func hostIsLocal(h string) bool {
	h = strings.TrimSuffix(strings.ToLower(strings.Trim(h, "[]")), ".")
	if h == "" {
		return false
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast()
}

func (a *App) fetch(u string, viaProxy int) (*http.Response, []byte, error) {
	return a.fetchUA(u, viaProxy, "Volfram/"+AppVersion)
}

func (a *App) deviceHeaders(req *http.Request) {
	a.store.mu.Lock()
	if a.store.DeviceID == "" {
		a.store.DeviceID = randHex(16)
		_ = a.store.Save()
	}
	id := a.store.DeviceID
	a.store.mu.Unlock()
	osName, osVer, model := deviceInfo()
	req.Header.Set("X-HWID", id)
	req.Header.Set("X-Device-OS", osName)
	req.Header.Set("X-Ver-OS", osVer)
	req.Header.Set("X-Device-Model", model)
}

func (a *App) fetchUA(u string, viaProxy int, ua string) (*http.Response, []byte, error) {
	tr := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 10 * time.Second, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxResponseHeaderBytes: 1 << 20}
	origLocal := false
	if pu, err := url.Parse(u); err == nil {
		origLocal = hostIsLocal(pu.Hostname())
	}
	if viaProxy == 0 && !origLocal {
		d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second, Control: func(network, address string, _ syscall.RawConn) error {
			host, _, _ := net.SplitHostPort(address)
			if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()) {
				return errors.New("адрес ведёт на этот компьютер — запрос отменён")
			}
			return nil
		}}
		tr.DialContext = d.DialContext
	}
	if viaProxy > 0 {
		pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", viaProxy))
		if rp := a.engine.rpSnapshot(); rp.User != "" && rp.Mixed == viaProxy {
			pu.User = url.UserPassword(rp.User, rp.Pass)
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	c := &http.Client{Timeout: 25 * time.Second, Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("слишком много перенаправлений")
		}
		if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return errors.New("сервер перенаправил с https на незащищённый http — запрос отменён")
		}
		if !origLocal && hostIsLocal(req.URL.Hostname()) {
			return errors.New("сервер перенаправил запрос в локальную сеть — запрос отменён")
		}
		return nil
	}}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	if strings.HasPrefix(ua, "v2rayN") || strings.HasPrefix(ua, "Happ") || strings.HasPrefix(ua, "v2rayNG") {
		a.deviceHeaders(req)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 400 {
		return resp, nil, fmt.Errorf("сервер подписки ответил %d", resp.StatusCode)
	}
	return resp, body, nil
}

var subUserAgents = []string{
	"v2rayN/7.10.0",
	"Happ/3.10.0",
	"v2rayNG/1.10.10",
	"sing-box 1.14.4",
	"clash-verge/v2.2.3 mihomo/1.19.10",
	"Volfram/" + AppVersion,
}

type subFetch struct {
	resp   *http.Response
	nodes  []*Node
	format string
}

const maxSubServers = 3000

func (a *App) fetchSubscription(u string) (*subFetch, error) {
	if strings.HasPrefix(strings.ToLower(u), "http://") {
		a.Log("app", "warn", "Подписка загружается по незащищённому http:// — список серверов можно подменить в пути. Попросите у провайдера https-ссылку")
	}
	proxyPort := 0
	var first *subFetch
	var firstErr error
	formats := []string{}
	for _, ua := range subUserAgents {
		resp, body, err := a.fetchUA(u, proxyPort, ua)
		if err != nil && proxyPort == 0 && a.engine.Status().State == "connected" {
			a.Log("app", "warn", "Подписка недоступна напрямую, пробую через VPN: "+err.Error())
			proxyPort = a.engine.Status().Port
			resp, body, err = a.fetchUA(u, proxyPort, ua)
		}
		if err != nil {
			if resp == nil {
				return nil, err
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		nodes, format := ParseSubscriptionBody(body)
		r := &subFetch{resp: resp, nodes: nodes, format: format}
		if first == nil {
			first = r
		}
		if len(nodes) > 0 {
			a.Log("app", "info", fmt.Sprintf("Подписка: формат «%s», User-Agent %s, серверов: %d", format, strings.Fields(ua)[0], len(nodes)))
			if resp.Header.Get("Subscription-Userinfo") == "" && first.resp != nil {
				for _, h := range []string{"Subscription-Userinfo", "Profile-Title", "Profile-Web-Page-Url", "Announce", "Profile-Update-Interval"} {
					if v := first.resp.Header.Get(h); v != "" {
						resp.Header.Set(h, v)
					}
				}
			}
			return r, nil
		}
		formats = append(formats, strings.Fields(ua)[0]+": "+format)
	}
	a.Log("app", "warn", "Подписка без поддерживаемых серверов. Ответы: "+strings.Join(formats, "; "))
	if first == nil {
		return nil, firstErr
	}
	return first, nil
}

func (a *App) UpdateSubscription(id string) error {
	a.store.mu.Lock()
	var sub *Subscription
	for _, s := range a.store.Subs {
		if s.ID == id {
			sub = s
		}
	}
	a.store.mu.Unlock()
	if sub == nil {
		return errors.New("подписка не найдена")
	}
	a.hub.Send("subUpdating", M{"id": id, "active": true})
	defer a.hub.Send("subUpdating", M{"id": id, "active": false})
	sf, err := a.fetchSubscription(sub.URL)
	if err != nil {
		a.store.mu.Lock()
		sub.Error = err.Error()
		_ = a.store.Save()
		a.store.mu.Unlock()
		a.pushServers()
		return fmt.Errorf("%s: %v", sub.Name, err)
	}
	resp, nodes := sf.resp, sf.nodes
	if len(nodes) > maxSubServers {
		a.Log("app", "warn", fmt.Sprintf("Подписка «%s»: %d серверов, загружены первые %d", sub.Name, len(nodes), maxSubServers))
		nodes = nodes[:maxSubServers]
	}
	if len(nodes) == 0 {
		a.store.mu.Lock()
		switch sf.format {
		case fmtHTML:
			sub.Error = "сервер вернул веб-страницу вместо списка серверов — проверьте, что это ссылка именно на подписку"
		case fmtHapp:
			sub.Error = "провайдер отдаёт только зашифрованные ссылки happ:// — их может открыть лишь приложение Happ"
		case fmtEmpty:
			sub.Error = "подписка пуста — возможно, она истекла или превышен лимит устройств"
		default:
			sub.Error = "в подписке не найдено поддерживаемых серверов"
		}
		_ = a.store.Save()
		a.store.mu.Unlock()
		a.pushServers()
		return fmt.Errorf("%s: %s", sub.Name, sub.Error)
	}
	a.store.mu.Lock()
	sub.Error = ""
	sub.Updated = time.Now().Unix()
	sub.Count = len(nodes)
	if v := resp.Header.Get("Subscription-Userinfo"); v != "" {
		for _, part := range strings.Split(v, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) != 2 {
				continue
			}
			n, _ := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64)
			switch strings.ToLower(kv[0]) {
			case "upload":
				sub.Upload = int64(n)
			case "download":
				sub.Download = int64(n)
			case "total":
				sub.Total = int64(n)
			case "expire":
				sub.Expire = int64(n)
			}
		}
	}
	if t := cleanText(decodeHeaderText(resp.Header.Get("Profile-Title")), 120); t != "" {
		sub.Name = t
	}
	sub.WebPage, _ = webURL(resp.Header.Get("Profile-Web-Page-Url"))
	sub.Announce = cleanText(decodeHeaderText(resp.Header.Get("Announce")), 1000)
	old := map[string]*Server{}
	var kept []*Server
	for _, s := range a.store.Servers {
		if s.SubID == sub.ID {
			old[s.ID] = s
		} else {
			kept = append(kept, s)
		}
	}
	var fresh []*Server
	seen := map[string]bool{}
	for _, n := range nodes {
		sv := serverFromNode(n, sub.ID)
		if seen[sv.ID] {
			continue
		}
		seen[sv.ID] = true
		if o := old[sv.ID]; o != nil {
			sv.Delay = o.Delay
			sv.Added = o.Added
			if o.Custom {
				sv.Name, sv.Custom = o.Name, true
			}
		}
		fresh = append(fresh, sv)
	}
	insertAt := len(kept)
	for i, s := range a.store.Servers {
		if s.SubID == sub.ID {
			insertAt = 0
			for _, k := range a.store.Servers[:i] {
				if k.SubID != sub.ID {
					insertAt++
				}
			}
			break
		}
	}
	merged := append([]*Server{}, kept[:insertAt]...)
	merged = append(merged, fresh...)
	merged = append(merged, kept[insertAt:]...)
	a.store.Servers = merged
	if a.store.Selected == "" || a.store.find(a.store.Selected) == nil {
		if len(fresh) > 0 && (a.store.Selected == "" || a.engine.Status().State != "connected") {
			a.store.Selected = fresh[0].ID
		}
	}
	_ = a.store.Save()
	a.store.mu.Unlock()
	a.Log("app", "info", fmt.Sprintf("Подписка «%s» обновлена: %d %s", sub.Name, len(fresh), pluralRu(len(fresh), "сервер", "сервера", "серверов")))
	a.pushServers()
	return nil
}

func (a *App) UpdateAllSubs() []string {
	a.store.mu.Lock()
	var ids []string
	for _, s := range a.store.Subs {
		ids = append(ids, s.ID)
	}
	a.store.mu.Unlock()
	var errs []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if err := a.UpdateSubscription(id); err != nil {
				mu.Lock()
				errs = append(errs, err.Error())
				mu.Unlock()
			}
		}(id)
	}
	wg.Wait()
	return errs
}

func (a *App) FetchIP(port int) {
	a.ipMu.Lock()
	gen := a.ipGen
	a.ipMu.Unlock()
	fresh := func() bool {
		st := a.engine.Status()
		ok := st.State == "idle"
		if port > 0 {
			ok = st.State == "connected" && st.Port == port
		}
		a.ipMu.Lock()
		defer a.ipMu.Unlock()
		return ok && gen == a.ipGen
	}
	time.Sleep(400 * time.Millisecond)
	type src struct {
		url   string
		parse func(m map[string]any) M
	}
	sources := []src{
		{"https://ipwho.is/?lang=ru", func(m map[string]any) M {
			conn, _ := m["connection"].(map[string]any)
			isp := ""
			if conn != nil {
				isp = anyStr(conn["isp"])
				if isp == "" {
					isp = anyStr(conn["org"])
				}
			}
			return M{"ip": anyStr(m["ip"]), "country": anyStr(m["country"]), "cc": anyStr(m["country_code"]), "city": anyStr(m["city"]), "isp": isp}
		}},
		{"https://api.ip.sb/geoip", func(m map[string]any) M {
			return M{"ip": anyStr(m["ip"]), "country": anyStr(m["country"]), "cc": anyStr(m["country_code"]), "city": anyStr(m["city"]), "isp": anyStr(m["isp"])}
		}},
		{"https://ifconfig.co/json", func(m map[string]any) M {
			return M{"ip": anyStr(m["ip"]), "country": anyStr(m["country"]), "cc": anyStr(m["country_iso"]), "city": anyStr(m["city"]), "isp": anyStr(m["asn_org"])}
		}},
	}
	for _, s := range sources {
		t0 := time.Now()
		_, body, err := a.fetch(s.url, port)
		if err != nil {
			continue
		}
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			continue
		}
		r := s.parse(m)
		if r["ip"] == "" {
			continue
		}
		r["latency"] = time.Since(t0).Milliseconds()
		r["direct"] = port == 0
		if !fresh() {
			return
		}
		a.ipMu.Lock()
		a.ip = r
		a.ipMu.Unlock()
		a.hub.Send("ip", r)
		return
	}
	if fresh() {
		a.hub.Send("ip", M{"error": "не удалось определить IP"})
	}
}

func (a *App) selectedServer() *Server {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	if sv := a.store.find(a.store.Selected); sv != nil {
		c := *sv
		return &c
	}
	if len(a.store.Servers) > 0 {
		a.store.Selected = a.store.Servers[0].ID
		c := *a.store.Servers[0]
		return &c
	}
	return nil
}

func (a *App) Connect() error {
	sv := a.selectedServer()
	if sv == nil {
		return errors.New("добавьте сервер или подписку")
	}
	a.store.mu.Lock()
	s := a.store.Settings
	a.store.mu.Unlock()
	a.ipMu.Lock()
	a.ip = nil
	a.ipGen++
	a.ipMu.Unlock()
	return a.engine.Connect(sv, s)
}

func (a *App) Shutdown() {
	a.engine.Disconnect()
}

func (a *App) StartBackground(autoConnect bool) {
	if isAndroid || !isAdmin() {
		for _, f := range []string{"config.json", "xray.json", "tester.json", "xtester.json"} {
			_ = os.Remove(filepath.Join(a.runDir, f))
		}
	}
	a.PrepareCores()
	a.store.mu.Lock()
	s := a.store.Settings
	a.store.mu.Unlock()
	cleanupStaleProxy(fmt.Sprintf("127.0.0.1:%d", s.MixedPort))
	go func() {
		if autoConnect || s.AutoConnect {
			if err := a.WaitCores(); err == nil {
				if err := a.Connect(); err != nil {
					if err == ErrNeedAdmin {
						a.needAdmin()
					} else {
						a.hub.Send("toast", M{"kind": "error", "text": err.Error()})
					}
				}
			}
		}
		if s.AutoUpdateSubs {
			time.Sleep(2 * time.Second)
			a.UpdateAllSubs()
			for range time.Tick(6 * time.Hour) {
				a.store.mu.Lock()
				on := a.store.Settings.AutoUpdateSubs
				a.store.mu.Unlock()
				if on {
					a.UpdateAllSubs()
				}
			}
		}
	}()
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(v)
}

func reply(w http.ResponseWriter, v any, err error) {
	if err == ErrCancelled {
		err = nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		code := "error"
		if err == ErrNeedAdmin {
			code = "need_admin"
		}
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(M{"ok": false, "error": err.Error(), "code": code})
		return
	}
	_ = json.NewEncoder(w).Encode(M{"ok": true, "data": v})
}

func (a *App) state() M {
	a.store.mu.Lock()
	b, _ := json.Marshal(a.store)
	a.store.mu.Unlock()
	var st M
	_ = json.Unmarshal(b, &st)
	a.ipMu.Lock()
	ip := a.ip
	a.ipMu.Unlock()
	status := a.engine.Status()
	if direct, _ := ip["direct"].(bool); ip != nil && direct != (status.State != "connected") {
		ip = nil
	}
	st["status"] = status
	st["admin"] = isAdmin()
	st["versions"] = a.versions
	st["coresReady"] = a.coresReady()
	st["ip"] = ip
	st["platform"] = platformName
	if !isAndroid {
		st["lanIPs"] = lanIPs()
	}
	return st
}

func lanIPs() []string {
	var out []string
	ifs, _ := net.Interfaces()
	for _, it := range ifs {
		if it.Flags&net.FlagUp == 0 || it.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := it.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipn.IP.To4()
			if ip == nil || !ip.IsPrivate() || (ip[0] == 172 && ip[1] == 19) {
				continue
			}
			out = append(out, ip.String())
		}
	}
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(uiFS, "ui")
	static := http.FileServer(http.FS(sub))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		static.ServeHTTP(w, r)
	}))
	api := func(path string, h func(w http.ResponseWriter, r *http.Request)) {
		mux.HandleFunc(path, h)
	}
	api("/api/state", func(w http.ResponseWriter, r *http.Request) { reply(w, a.state(), nil) })
	api("/api/events", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no stream", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		c := a.hub.add()
		defer a.hub.remove(c)
		fmt.Fprintf(w, "data: {\"type\":\"hello\"}\n\n")
		fl.Flush()
		ping := time.NewTicker(15 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case b := <-c:
				fmt.Fprintf(w, "data: %s\n\n", b)
				fl.Flush()
			case <-ping.C:
				fmt.Fprintf(w, ": ping\n\n")
				fl.Flush()
			}
		}
	})
	api("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			a.logMu.Lock()
			a.logs = nil
			a.logMu.Unlock()
			reply(w, nil, nil)
			return
		}
		a.logMu.Lock()
		l := append([]LogEntry{}, a.logs...)
		a.logMu.Unlock()
		reply(w, l, nil)
	})
	api("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID string `json:"id"`
		}
		_ = readJSON(r, &req)
		if req.ID != "" {
			a.store.mu.Lock()
			if a.store.find(req.ID) != nil {
				a.store.Selected = req.ID
				_ = a.store.Save()
			}
			a.store.mu.Unlock()
		}
		reply(w, nil, a.Connect())
	})
	api("/api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		a.engine.Disconnect()
		reply(w, nil, nil)
	})
	api("/api/select", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID string `json:"id"`
		}
		if err := readJSON(r, &req); err != nil {
			reply(w, nil, err)
			return
		}
		if !a.selectServer(req.ID) {
			reply(w, nil, errors.New("сервер не найден"))
			return
		}
		reconnect := a.engine.Status().State == "connected" && a.engine.Status().ServerID != req.ID
		if reconnect {
			go func() {
				if err := a.Connect(); err != nil {
					a.hub.Send("toast", M{"kind": "error", "text": err.Error()})
				}
			}()
		}
		reply(w, M{"reconnect": reconnect}, nil)
	})
	api("/api/servers/add", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text string `json:"text"`
		}
		if err := readJSON(r, &req); err != nil {
			reply(w, nil, err)
			return
		}
		added, subs, errs := a.AddText(req.Text)
		if added == 0 && subs == 0 {
			msg := "не найдено поддерживаемых ссылок"
			if len(errs) > 0 {
				msg = errs[0]
			}
			reply(w, nil, errors.New(msg))
			return
		}
		reply(w, M{"added": added, "subs": subs, "errors": errs}, nil)
	})
	api("/api/clipboard/import", func(w http.ResponseWriter, r *http.Request) {
		text, err := readClipboard()
		if err != nil || strings.TrimSpace(text) == "" {
			reply(w, nil, errors.New("буфер обмена пуст"))
			return
		}
		added, subs, errs := a.AddText(text)
		if added == 0 && subs == 0 {
			msg := "в буфере нет поддерживаемых ссылок"
			if len(errs) > 0 {
				msg = errs[0]
			}
			reply(w, nil, errors.New(msg))
			return
		}
		reply(w, M{"added": added, "subs": subs, "errors": errs}, nil)
	})
	api("/api/clipboard/copy", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID   string `json:"id"`
			Text string `json:"text"`
		}
		_ = readJSON(r, &req)
		text := req.Text
		if req.ID != "" {
			a.store.mu.Lock()
			if sv := a.store.find(req.ID); sv != nil {
				text = sv.Link
			}
			a.store.mu.Unlock()
		}
		reply(w, nil, writeClipboard(text))
	})
	api("/api/servers/delete", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IDs []string `json:"ids"`
		}
		if err := readJSON(r, &req); err != nil {
			reply(w, nil, err)
			return
		}
		del := map[string]bool{}
		for _, id := range req.IDs {
			del[id] = true
		}
		a.store.mu.Lock()
		var keep []*Server
		for _, s := range a.store.Servers {
			if !del[s.ID] {
				keep = append(keep, s)
			}
		}
		if keep == nil {
			keep = []*Server{}
		}
		a.store.Servers = keep
		if del[a.store.Selected] {
			a.store.Selected = ""
			if len(keep) > 0 {
				a.store.Selected = keep[0].ID
			}
		}
		_ = a.store.Save()
		a.store.mu.Unlock()
		a.pushServers()
		reply(w, nil, nil)
	})
	api("/api/servers/rename", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID, Name string
		}
		if err := readJSON(r, &req); err != nil {
			reply(w, nil, err)
			return
		}
		a.store.mu.Lock()
		if sv := a.store.find(req.ID); sv != nil && strings.TrimSpace(req.Name) != "" {
			sv.Name = cleanText(req.Name, 120)
			sv.Custom = true
			_ = a.store.Save()
		}
		a.store.mu.Unlock()
		a.pushServers()
		reply(w, nil, nil)
	})
	api("/api/servers/test", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IDs []string `json:"ids"`
		}
		_ = readJSON(r, &req)
		want := map[string]bool{}
		for _, id := range req.IDs {
			want[id] = true
		}
		a.store.mu.Lock()
		var list []*Server
		for _, s := range a.store.Servers {
			if len(want) == 0 || want[s.ID] {
				c := *s
				list = append(list, &c)
			}
		}
		s := a.store.Settings
		a.store.mu.Unlock()
		go a.engine.TestDelays(list, s)
		reply(w, M{"count": len(list)}, nil)
	})
	api("/api/servers/config", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		a.store.mu.Lock()
		sv := a.store.find(id)
		s := a.store.Settings
		a.store.mu.Unlock()
		if sv == nil {
			reply(w, nil, errors.New("сервер не найден"))
			return
		}
		n, err := ParseLink(sv.Link)
		if err != nil {
			reply(w, nil, err)
			return
		}
		var out M
		if n.NeedsXray() {
			out, err = BuildXray(n, 10809, s.LogLevel)
		} else {
			o, _, e2 := SingboxOutbound(n, "proxy")
			out, err = o, e2
		}
		reply(w, M{"core": n.Core(), "outbound": out, "link": sv.Link}, err)
	})
	api("/api/subs/add", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ URL, Name string }
		if err := readJSON(r, &req); err != nil {
			reply(w, nil, err)
			return
		}
		_, err := a.AddSubscription(req.URL, req.Name)
		a.pushServers()
		reply(w, nil, err)
	})
	api("/api/subs/update", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ ID string }
		_ = readJSON(r, &req)
		if req.ID == "" {
			errs := a.UpdateAllSubs()
			if len(errs) > 0 {
				reply(w, nil, errors.New(strings.Join(errs, "; ")))
				return
			}
			reply(w, nil, nil)
			return
		}
		reply(w, nil, a.UpdateSubscription(req.ID))
	})
	api("/api/subs/edit", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ ID, Name, URL string }
		if err := readJSON(r, &req); err != nil {
			reply(w, nil, err)
			return
		}
		nu := ""
		if t := strings.TrimSpace(req.URL); t != "" {
			pu, err := url.Parse(t)
			if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
				reply(w, nil, errors.New("некорректный адрес подписки"))
				return
			}
			nu = pu.String()
		}
		a.store.mu.Lock()
		for _, s := range a.store.Subs {
			if s.ID == req.ID {
				if strings.TrimSpace(req.Name) != "" {
					s.Name = cleanText(req.Name, 120)
				}
				if nu != "" {
					s.URL = nu
				}
			}
		}
		_ = a.store.Save()
		a.store.mu.Unlock()
		a.pushServers()
		reply(w, nil, nil)
	})
	api("/api/subs/delete", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ ID string }
		if err := readJSON(r, &req); err != nil {
			reply(w, nil, err)
			return
		}
		a.store.mu.Lock()
		var subs []*Subscription
		for _, s := range a.store.Subs {
			if s.ID != req.ID {
				subs = append(subs, s)
			}
		}
		if subs == nil {
			subs = []*Subscription{}
		}
		a.store.Subs = subs
		var keep []*Server
		for _, s := range a.store.Servers {
			if s.SubID != req.ID {
				keep = append(keep, s)
			}
		}
		if keep == nil {
			keep = []*Server{}
		}
		a.store.Servers = keep
		if a.store.find(a.store.Selected) == nil {
			a.store.Selected = ""
			if len(keep) > 0 {
				a.store.Selected = keep[0].ID
			}
		}
		_ = a.store.Save()
		a.store.mu.Unlock()
		a.pushServers()
		reply(w, nil, nil)
	})
	api("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		var patch map[string]json.RawMessage
		if err := readJSON(r, &patch); err != nil {
			reply(w, nil, err)
			return
		}
		a.store.mu.Lock()
		cur, _ := json.Marshal(a.store.Settings)
		var m map[string]json.RawMessage
		_ = json.Unmarshal(cur, &m)
		for k, v := range patch {
			m[k] = v
		}
		nb, _ := json.Marshal(m)
		var ns Settings
		err := json.Unmarshal(nb, &ns)
		old0 := a.store.Settings
		if ns.PingMode != "tcp" && ns.PingMode != "get" {
			ns.PingMode = defaultPingMode
		}
		if err == nil {
			ns.LanUser, ns.LanPass = old0.LanUser, old0.LanPass
			err = validateSettings(&ns)
		}
		old := a.store.Settings
		if err == nil {
			a.store.Settings = ns
			_ = a.store.Save()
		}
		a.store.mu.Unlock()
		if err != nil {
			reply(w, nil, err)
			return
		}
		if ns.Autostart != old.Autostart {
			if e := setAutostart(ns.Autostart); e != nil {
				a.Log("app", "warn", "Автозапуск: "+e.Error())
			}
		}
		_, sortOnly := patch["sort"]
		restart := a.engine.Status().State == "connected" && !(len(patch) == 1 && sortOnly) && runtimeChanged(old, ns)
		if restart {
			go func() {
				if err := a.Connect(); err != nil {
					if err == ErrNeedAdmin {
						a.needAdmin()
					} else {
						a.hub.Send("toast", M{"kind": "error", "text": err.Error()})
					}
				}
			}()
		}
		a.hub.Send("settings", ns)
		reply(w, M{"restart": restart}, nil)
	})
	api("/api/connections", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			reply(w, nil, a.engine.CloseConnection(r.URL.Query().Get("id")))
			return
		}
		c, err := a.engine.Connections()
		reply(w, c, err)
	})
	api("/api/ip", func(w http.ResponseWriter, r *http.Request) {
		st := a.engine.Status()
		switch st.State {
		case "connected":
			go a.FetchIP(st.Port)
		case "idle":
			go a.FetchIP(0)
		}
		reply(w, nil, nil)
	})
	api("/api/apps", func(w http.ResponseWriter, r *http.Request) {
		list, err := listApps()
		reply(w, list, err)
	})
	api("/api/appicon", func(w http.ResponseWriter, r *http.Request) {
		b, err := appIcon(r.URL.Query().Get("pkg"))
		if err != nil || len(b) == 0 {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "private, max-age=86400")
		_, _ = w.Write(b)
	})
	api("/api/admin/restart", func(w http.ResponseWriter, r *http.Request) {
		if a.onRestartAdmin == nil {
			reply(w, nil, errors.New("недоступно на этой платформе"))
			return
		}
		reply(w, nil, a.onRestartAdmin())
	})
	api("/api/open", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ URL string }
		_ = readJSON(r, &req)
		if u, ok := webURL(req.URL); ok {
			openURL(u)
		} else if req.URL == "data" {
			openURL(a.dataDir)
		}
		reply(w, nil, nil)
	})
	api("/api/vpnsettings", func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, openVPNSettings())
	})
	api("/api/quit", func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, nil)
		if a.onQuit != nil {
			go a.onQuit()
		}
	})
	return mux
}

func runtimeChanged(a, b Settings) bool {
	a.Sort, b.Sort = "", ""
	a.AutoConnect, b.AutoConnect = false, false
	a.Autostart, b.Autostart = false, false
	a.CloseToTray, b.CloseToTray = false, false
	a.AutoUpdateSubs, b.AutoUpdateSubs = false, false
	a.TestURL, b.TestURL = "", ""
	a.PingMode, b.PingMode = "", ""
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) != string(jb)
}

func (a *App) Serve() (string, error) {
	addr := "127.0.0.1:0"
	if p := os.Getenv("VOLFRAM_DEV_PORT"); p != "" {
		addr = "127.0.0.1:" + p
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: a.guard(a.Handler()), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	go srv.Serve(l)
	return fmt.Sprintf("http://127.0.0.1:%d/?t=%s", l.Addr().(*net.TCPAddr).Port, a.token), nil
}

var _ = sort.Strings
