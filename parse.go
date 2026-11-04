package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Node struct {
	Proto    string
	Name     string
	Host     string
	Port     int
	Ports    string
	UUID     string
	Password string
	Method   string
	Flow     string
	User     string

	Security string
	SNI      string
	ALPN     []string
	FP       string
	PBK      string
	SID      string
	SPX      string
	PQV      string
	Insecure bool

	Net         string
	Path        string
	HostHdr     string
	ServiceName string
	HeaderType  string
	Mode        string
	Extra       string
	Seed        string
	Authority   string

	AlterID    int
	VmessSec   string
	Encryption string

	Plugin     string
	PluginOpts string

	Obfs         string
	ObfsPassword string
	UpMbps       int
	DownMbps     int

	CC       string
	UDPRelay string

	PrivKey  string
	PubKey   string
	PSK      string
	Address  []string
	Reserved []int
	MTU      int

	Link string
}

type parsedURL struct {
	scheme, userinfo, host, port, path, rawQuery, fragment string
	q                                                      url.Values
}

func unesc(s string) string {
	if v, err := url.PathUnescape(s); err == nil {
		return v
	}
	return s
}

func splitURL(link string) (*parsedURL, error) {
	p := &parsedURL{}
	i := strings.Index(link, "://")
	if i < 0 {
		return nil, errors.New("нет схемы")
	}
	p.scheme = strings.ToLower(link[:i])
	rest := link[i+3:]
	if j := strings.Index(rest, "#"); j >= 0 {
		p.fragment = unesc(rest[j+1:])
		rest = rest[:j]
	}
	if j := strings.Index(rest, "?"); j >= 0 {
		p.rawQuery = rest[j+1:]
		rest = rest[:j]
	}
	if j := strings.Index(rest, "/"); j >= 0 {
		p.path = rest[j:]
		rest = rest[:j]
	}
	if j := strings.LastIndex(rest, "@"); j >= 0 {
		p.userinfo = rest[:j]
		rest = rest[j+1:]
	}
	hp := rest
	if strings.HasPrefix(hp, "[") {
		k := strings.Index(hp, "]")
		if k < 0 {
			return nil, errors.New("некорректный IPv6 адрес")
		}
		p.host = hp[1:k]
		if len(hp) > k+1 && hp[k+1] == ':' {
			p.port = hp[k+2:]
		}
	} else if k := strings.LastIndex(hp, ":"); k >= 0 {
		p.host, p.port = hp[:k], hp[k+1:]
	} else {
		p.host = hp
	}
	p.q, _ = url.ParseQuery(p.rawQuery)
	if p.q == nil {
		p.q = url.Values{}
	}
	return p, nil
}

func (p *parsedURL) get(keys ...string) string {
	for _, k := range keys {
		if v := p.q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func truthy(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "1" || s == "true" || s == "yes"
}

func b64decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\r", "", "\n", "", " ", "", "\t", "").Replace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	if m := len(s) % 4; m != 0 {
		if b, err := base64.StdEncoding.DecodeString(s + strings.Repeat("=", 4-m)); err == nil {
			return b, nil
		}
		if b, err := base64.URLEncoding.DecodeString(s + strings.Repeat("=", 4-m)); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("не base64")
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 || n > 65535 {
		return 0, fmt.Errorf("некорректный порт %q", s)
	}
	return n, nil
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func anyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case bool:
		if t {
			return "1"
		}
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func SplitInput(text string) []string {
	text = strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	if text == "" {
		return nil
	}
	if !strings.Contains(text, "://") {
		if b, err := b64decode(text); err == nil {
			text = string(b)
		}
	}
	var out []string
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.Contains(line, "://") {
			out = append(out, line)
		}
	}
	return out
}

func ParseLink(link string) (*Node, error) {
	link = strings.TrimSpace(link)
	low := strings.ToLower(link)
	var n *Node
	var err error
	switch {
	case strings.HasPrefix(low, "vmess://"):
		n, err = parseVmess(link)
	case strings.HasPrefix(low, "vless://"):
		n, err = parseVlessTrojan(link, "vless")
	case strings.HasPrefix(low, "trojan://"):
		n, err = parseVlessTrojan(link, "trojan")
	case strings.HasPrefix(low, "ss://"):
		n, err = parseSS(link)
	case strings.HasPrefix(low, "hysteria2://"), strings.HasPrefix(low, "hy2://"):
		n, err = parseHy2(link)
	case strings.HasPrefix(low, "hysteria://"):
		n, err = parseHy1(link)
	case strings.HasPrefix(low, "tuic://"):
		n, err = parseTuic(link)
	case strings.HasPrefix(low, "wireguard://"), strings.HasPrefix(low, "wg://"):
		n, err = parseWG(link)
	case strings.HasPrefix(low, "socks://"), strings.HasPrefix(low, "socks5://"), strings.HasPrefix(low, "socks5h://"):
		n, err = parseSocks(link)
	case strings.HasPrefix(low, "anytls://"):
		n, err = parseAnyTLS(link)
	case strings.HasPrefix(low, "naive+https://"), strings.HasPrefix(low, "naive+quic://"), strings.HasPrefix(low, "naive://"):
		n, err = parseNaive(link)
	default:
		i := strings.Index(link, "://")
		if i < 0 {
			return nil, errors.New("не похоже на ссылку")
		}
		return nil, fmt.Errorf("протокол %s не поддерживается", link[:i])
	}
	if err != nil {
		return nil, err
	}
	if n.Host == "" {
		return nil, errors.New("не указан адрес сервера")
	}
	n.Link = link
	if strings.TrimSpace(n.Name) == "" {
		n.Name = fmt.Sprintf("%s %s:%d", strings.ToUpper(n.Proto), n.Host, n.Port)
	}
	n.Name = strings.TrimSpace(n.Name)
	return n, nil
}

func parseVmess(link string) (*Node, error) {
	body := link[len("vmess://"):]
	name := ""
	if j := strings.Index(body, "#"); j >= 0 {
		name = unesc(body[j+1:])
		body = body[:j]
	}
	raw, err := b64decode(body)
	if err != nil {
		p, err2 := splitURL(link)
		if err2 != nil || p.userinfo == "" {
			return nil, errors.New("не удалось декодировать vmess")
		}
		n := &Node{Proto: "vmess", Name: p.fragment, Host: p.host, UUID: unesc(p.userinfo), VmessSec: "auto"}
		if n.Port, err = parsePort(p.port); err != nil {
			return nil, err
		}
		fillStream(n, p)
		if s := p.get("encryption"); s != "" {
			n.VmessSec = s
		}
		return n, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, errors.New("некорректный JSON vmess")
	}
	n := &Node{Proto: "vmess", Name: anyStr(m["ps"]), Host: strings.TrimSpace(anyStr(m["add"])), UUID: anyStr(m["id"])}
	if name != "" && n.Name == "" {
		n.Name = name
	}
	if n.Port, err = parsePort(anyStr(m["port"])); err != nil {
		return nil, err
	}
	n.AlterID, _ = strconv.Atoi(anyStr(m["aid"]))
	n.VmessSec = anyStr(m["scy"])
	if n.VmessSec == "" {
		n.VmessSec = "auto"
	}
	n.Net = strings.ToLower(anyStr(m["net"]))
	n.HeaderType = anyStr(m["type"])
	n.HostHdr = anyStr(m["host"])
	n.Path = anyStr(m["path"])
	if strings.EqualFold(anyStr(m["tls"]), "tls") {
		n.Security = "tls"
	} else if strings.EqualFold(anyStr(m["tls"]), "reality") {
		n.Security = "reality"
		n.PBK = anyStr(m["pbk"])
		n.SID = anyStr(m["sid"])
	}
	n.SNI = anyStr(m["sni"])
	n.ALPN = splitList(anyStr(m["alpn"]))
	n.FP = anyStr(m["fp"])
	n.Insecure = truthy(anyStr(m["allowInsecure"])) || truthy(anyStr(m["skip-cert-verify"]))
	if n.Net == "grpc" {
		n.ServiceName = n.Path
		if n.HeaderType != "" && n.HeaderType != "none" {
			n.Mode = n.HeaderType
		}
	}
	if n.Net == "xhttp" || n.Net == "splithttp" {
		n.Mode = n.HeaderType
	}
	if n.Net == "kcp" {
		n.Seed = n.Path
	}
	if n.Net == "" {
		n.Net = "tcp"
	}
	return n, nil
}

func fillStream(n *Node, p *parsedURL) {
	n.Net = strings.ToLower(p.get("type", "net"))
	if n.Net == "" {
		n.Net = "tcp"
	}
	if n.Net == "splithttp" {
		n.Net = "xhttp"
	}
	n.Security = strings.ToLower(p.get("security"))
	n.SNI = p.get("sni", "peer", "servername")
	n.FP = p.get("fp", "fingerprint")
	n.PBK = p.get("pbk", "publicKey")
	n.SID = p.get("sid", "shortId")
	n.SPX = p.get("spx", "spiderX")
	n.PQV = p.get("pqv", "mldsa65Verify")
	n.ALPN = splitList(p.get("alpn"))
	n.Insecure = truthy(p.get("allowInsecure", "insecure", "allow_insecure", "skip-cert-verify"))
	n.HostHdr = p.get("host")
	n.Path = p.get("path")
	n.ServiceName = p.get("serviceName", "service_name")
	n.HeaderType = p.get("headerType")
	n.Mode = p.get("mode")
	n.Extra = p.get("extra")
	n.Seed = p.get("seed")
	n.Authority = p.get("authority")
	if n.Net == "grpc" && n.ServiceName == "" {
		n.ServiceName = n.Path
	}
}

func parseVlessTrojan(link, proto string) (*Node, error) {
	p, err := splitURL(link)
	if err != nil {
		return nil, err
	}
	n := &Node{Proto: proto, Name: p.fragment, Host: p.host}
	if n.Port, err = parsePort(p.port); err != nil {
		return nil, err
	}
	fillStream(n, p)
	if proto == "vless" {
		n.UUID = unesc(p.userinfo)
		n.Flow = p.get("flow")
		n.Encryption = p.get("encryption")
		if n.UUID == "" {
			return nil, errors.New("не указан UUID")
		}
	} else {
		n.Password = unesc(p.userinfo)
		if n.Security == "" {
			n.Security = "tls"
		}
		if n.Password == "" {
			return nil, errors.New("не указан пароль")
		}
	}
	if n.Security == "xtls" {
		n.Security = "tls"
	}
	return n, nil
}

func parseSS(link string) (*Node, error) {
	body := link[len("ss://"):]
	name := ""
	if j := strings.Index(body, "#"); j >= 0 {
		name = unesc(body[j+1:])
		body = body[:j]
	}
	query := ""
	if j := strings.Index(body, "?"); j >= 0 {
		query = body[j+1:]
		body = body[:j]
	}
	body = strings.TrimSuffix(body, "/")
	if !strings.Contains(body, "@") {
		raw, err := b64decode(body)
		if err != nil {
			return nil, errors.New("не удалось декодировать ss")
		}
		body = string(raw)
	}
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return nil, errors.New("некорректная ss ссылка")
	}
	ui, hp := body[:at], body[at+1:]
	ui = unesc(ui)
	if !strings.Contains(ui, ":") {
		raw, err := b64decode(ui)
		if err != nil {
			return nil, errors.New("некорректные учётные данные ss")
		}
		ui = string(raw)
	}
	c := strings.Index(ui, ":")
	if c < 0 {
		return nil, errors.New("некорректные учётные данные ss")
	}
	p, err := splitURL("ss://" + hp)
	if err != nil {
		return nil, err
	}
	n := &Node{Proto: "ss", Name: name, Host: p.host, Method: strings.ToLower(ui[:c]), Password: ui[c+1:]}
	if n.Port, err = parsePort(p.port); err != nil {
		return nil, err
	}
	q, _ := url.ParseQuery(query)
	if pl := q.Get("plugin"); pl != "" {
		parts := strings.SplitN(pl, ";", 2)
		n.Plugin = parts[0]
		if n.Plugin == "simple-obfs" {
			n.Plugin = "obfs-local"
		}
		if len(parts) > 1 {
			n.PluginOpts = parts[1]
		}
	}
	return n, nil
}

func parseHy2(link string) (*Node, error) {
	p, err := splitURL(link)
	if err != nil {
		return nil, err
	}
	n := &Node{Proto: "hysteria2", Name: p.fragment, Host: p.host, Password: unesc(p.userinfo), Security: "tls"}
	if n.Password == "" {
		n.Password = p.get("auth", "password")
	}
	portStr := p.port
	if strings.ContainsAny(portStr, ",-") {
		parts := splitList(portStr)
		first := parts[0]
		if strings.Contains(first, "-") {
			first = strings.SplitN(first, "-", 2)[0]
		}
		if n.Port, err = parsePort(first); err != nil {
			return nil, err
		}
		n.Ports = portStr
	} else if portStr == "" {
		n.Port = 443
	} else if n.Port, err = parsePort(portStr); err != nil {
		return nil, err
	}
	if mp := p.get("mport", "ports"); mp != "" {
		n.Ports = mp
	}
	n.SNI = p.get("sni", "peer")
	n.Insecure = truthy(p.get("insecure", "allowInsecure", "skip-cert-verify"))
	n.Obfs = p.get("obfs")
	n.ObfsPassword = p.get("obfs-password", "obfs_password", "obfsParam")
	n.ALPN = splitList(p.get("alpn"))
	n.UpMbps, _ = strconv.Atoi(p.get("upmbps", "up"))
	n.DownMbps, _ = strconv.Atoi(p.get("downmbps", "down"))
	return n, nil
}

func parseHy1(link string) (*Node, error) {
	p, err := splitURL(link)
	if err != nil {
		return nil, err
	}
	n := &Node{Proto: "hysteria", Name: p.fragment, Host: p.host, Security: "tls"}
	if n.Port, err = parsePort(p.port); err != nil {
		return nil, err
	}
	n.Password = p.get("auth", "auth_str")
	n.SNI = p.get("peer", "sni")
	n.Insecure = truthy(p.get("insecure", "allowInsecure"))
	n.ALPN = splitList(p.get("alpn"))
	n.ObfsPassword = p.get("obfsParam", "obfs-password")
	n.UpMbps, _ = strconv.Atoi(p.get("upmbps", "up"))
	n.DownMbps, _ = strconv.Atoi(p.get("downmbps", "down"))
	if n.UpMbps == 0 {
		n.UpMbps = 50
	}
	if n.DownMbps == 0 {
		n.DownMbps = 200
	}
	return n, nil
}

func parseTuic(link string) (*Node, error) {
	p, err := splitURL(link)
	if err != nil {
		return nil, err
	}
	n := &Node{Proto: "tuic", Name: p.fragment, Host: p.host, Security: "tls"}
	if n.Port, err = parsePort(p.port); err != nil {
		return nil, err
	}
	ui := unesc(p.userinfo)
	if c := strings.Index(ui, ":"); c >= 0 {
		n.UUID, n.Password = ui[:c], ui[c+1:]
	} else {
		n.UUID = ui
		n.Password = p.get("password")
	}
	n.SNI = p.get("sni", "peer")
	n.ALPN = splitList(p.get("alpn"))
	n.Insecure = truthy(p.get("allow_insecure", "insecure", "allowInsecure"))
	n.CC = p.get("congestion_control", "congestion")
	n.UDPRelay = p.get("udp_relay_mode")
	return n, nil
}

func parseWG(link string) (*Node, error) {
	p, err := splitURL(link)
	if err != nil {
		return nil, err
	}
	n := &Node{Proto: "wireguard", Name: p.fragment, Host: p.host}
	if n.Port, err = parsePort(p.port); err != nil {
		return nil, err
	}
	n.PrivKey = unesc(p.userinfo)
	if n.PrivKey == "" {
		n.PrivKey = p.get("privatekey", "private_key", "secretKey")
	}
	n.PubKey = p.get("publickey", "public_key", "peer_public_key", "publicKey")
	n.PSK = p.get("presharedkey", "pre_shared_key", "psk")
	n.Address = splitList(p.get("address", "ip", "local_address"))
	for i, a := range n.Address {
		if !strings.Contains(a, "/") {
			if strings.Contains(a, ":") {
				n.Address[i] = a + "/128"
			} else {
				n.Address[i] = a + "/32"
			}
		}
	}
	if len(n.Address) == 0 {
		n.Address = []string{"10.0.0.2/32"}
	}
	n.MTU, _ = strconv.Atoi(p.get("mtu"))
	for _, r := range splitList(p.get("reserved")) {
		if v, err := strconv.Atoi(r); err == nil {
			n.Reserved = append(n.Reserved, v)
		}
	}
	if n.PrivKey == "" || n.PubKey == "" {
		return nil, errors.New("не указаны ключи WireGuard")
	}
	return n, nil
}

func parseSocks(link string) (*Node, error) {
	p, err := splitURL(link)
	if err != nil {
		return nil, err
	}
	n := &Node{Proto: "socks", Name: p.fragment, Host: p.host}
	if n.Port, err = parsePort(p.port); err != nil {
		return nil, err
	}
	ui := unesc(p.userinfo)
	if ui != "" && !strings.Contains(ui, ":") {
		if raw, err := b64decode(ui); err == nil {
			ui = string(raw)
		}
	}
	if c := strings.Index(ui, ":"); c >= 0 {
		n.User, n.Password = ui[:c], ui[c+1:]
	} else {
		n.User = ui
	}
	return n, nil
}

func parseAnyTLS(link string) (*Node, error) {
	p, err := splitURL(link)
	if err != nil {
		return nil, err
	}
	n := &Node{Proto: "anytls", Name: p.fragment, Host: p.host, Password: unesc(p.userinfo), Security: "tls"}
	if n.Port, err = parsePort(p.port); err != nil {
		return nil, err
	}
	n.SNI = p.get("sni", "peer")
	n.Insecure = truthy(p.get("insecure", "allowInsecure"))
	n.ALPN = splitList(p.get("alpn"))
	n.FP = p.get("fp")
	return n, nil
}

func parseNaive(link string) (*Node, error) {
	p, err := splitURL(link)
	if err != nil {
		return nil, err
	}
	n := &Node{Proto: "naive", Name: p.fragment, Host: p.host, Security: "tls"}
	if p.port == "" {
		n.Port = 443
	} else if n.Port, err = parsePort(p.port); err != nil {
		return nil, err
	}
	if strings.HasPrefix(p.scheme, "naive+quic") {
		n.Net = "quic"
	}
	ui := unesc(p.userinfo)
	if c := strings.Index(ui, ":"); c >= 0 {
		n.User, n.Password = ui[:c], ui[c+1:]
	} else {
		n.User = ui
	}
	n.SNI = p.get("sni", "peer")
	return n, nil
}

func (n *Node) NeedsXray() bool {
	switch n.Proto {
	case "vless", "vmess", "trojan":
	default:
		return false
	}
	switch n.Net {
	case "xhttp", "kcp", "mkcp", "quic", "raw":
		return true
	}
	if n.Net == "tcp" && strings.EqualFold(n.HeaderType, "http") {
		return true
	}
	if n.Proto == "vless" && n.Encryption != "" && n.Encryption != "none" {
		return true
	}
	if n.Security == "reality" && (n.Proto == "vless" || n.Proto == "trojan") {
		return true
	}
	return false
}

func (n *Node) XrayRefusal() string {
	if !n.NeedsXray() || (n.Security != "" && n.Security != "none") {
		return ""
	}
	if n.Proto == "vless" && n.Encryption != "" && n.Encryption != "none" {
		return ""
	}
	if n.Proto != "vless" && n.Proto != "trojan" {
		return ""
	}
	if ip := net.ParseIP(strings.Trim(n.Host, "[]")); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		return ""
	}
	return "Xray-core запрещает " + strings.ToUpper(n.Proto) + " без TLS/Reality к публичным серверам — этот сервер настроен без шифрования, попросите у провайдера конфиг с TLS или Reality"
}

func (n *Node) Core() string {
	if n.NeedsXray() {
		return "xray"
	}
	return "sing-box"
}

func (n *Node) Tags() []string {
	var t []string
	switch n.Proto {
	case "vless", "vmess", "trojan":
		net := map[string]string{"tcp": "TCP", "raw": "RAW", "ws": "WS", "grpc": "gRPC", "http": "H2", "h2": "H2", "httpupgrade": "HTTPUpgrade", "xhttp": "XHTTP", "kcp": "mKCP", "mkcp": "mKCP", "quic": "QUIC"}[n.Net]
		if net == "" {
			net = strings.ToUpper(n.Net)
		}
		t = append(t, net)
		switch n.Security {
		case "reality":
			t = append(t, "Reality")
		case "tls":
			t = append(t, "TLS")
		}
		if strings.Contains(n.Flow, "vision") {
			t = append(t, "Vision")
		}
	case "ss":
		t = append(t, ssShort(n.Method))
		if n.Plugin != "" {
			t = append(t, n.Plugin)
		}
	case "hysteria2", "hysteria", "tuic":
		t = append(t, "QUIC")
		if n.Obfs != "" || n.ObfsPassword != "" {
			t = append(t, "Obfs")
		}
		if n.Ports != "" {
			t = append(t, "Port hop")
		}
	case "wireguard":
		t = append(t, "UDP")
	case "naive":
		if n.Net == "quic" {
			t = append(t, "QUIC")
		} else {
			t = append(t, "HTTPS")
		}
	case "anytls":
		t = append(t, "TLS")
	}
	if n.NeedsXray() {
		t = append(t, "Xray")
	}
	return t
}

func linkID(link string) string {
	h := sha1.Sum([]byte(strings.TrimSpace(link)))
	return hex.EncodeToString(h[:6])
}

func ssShort(m string) string {
	m = strings.ToLower(m)
	switch {
	case strings.HasPrefix(m, "2022-"):
		return "SS-2022"
	case strings.Contains(m, "chacha20"):
		return "ChaCha20"
	case strings.Contains(m, "aes-256"):
		return "AES-256"
	case strings.Contains(m, "aes-128"):
		return "AES-128"
	case m == "none" || m == "plain":
		return "Plain"
	}
	return strings.ToUpper(m)
}
