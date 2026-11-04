package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func mOf(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return t
	case map[any]any:
		m := map[string]any{}
		for k, x := range t {
			m[fmt.Sprint(k)] = x
		}
		return m
	}
	return nil
}

func lOf(v any) []any {
	if t, ok := v.([]any); ok {
		return t
	}
	return nil
}

func sOf(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case []any:
		if len(t) > 0 {
			return sOf(t[0])
		}
		return ""
	}
	return fmt.Sprint(v)
}

func iOf(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	}
	return 0
}

func bOf(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return truthy(t)
	case float64:
		return t != 0
	case int:
		return t != 0
	}
	return false
}

func strList(v any) []string {
	switch t := v.(type) {
	case string:
		return splitList(t)
	case []any:
		var out []string
		for _, x := range t {
			if s := sOf(x); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func intList(v any) []int {
	switch t := v.(type) {
	case []any:
		var out []int
		for _, x := range t {
			out = append(out, iOf(x))
		}
		return out
	case string:
		var out []int
		for _, s := range splitList(t) {
			if n, err := strconv.Atoi(s); err == nil {
				out = append(out, n)
			}
		}
		if len(out) == 0 {
			if b, err := base64.StdEncoding.DecodeString(t); err == nil {
				for _, c := range b {
					out = append(out, int(c))
				}
			}
		}
		return out
	}
	return nil
}

func hdrHost(v any) string {
	h := mOf(v)
	for k, x := range h {
		if strings.EqualFold(k, "host") {
			return sOf(x)
		}
	}
	return ""
}

var mbpsRe = regexp.MustCompile(`(?i)^\s*([\d.]+)\s*([kmg]?)(bps)?\s*$`)

func mbps(v any) int {
	s := sOf(v)
	if s == "" {
		return 0
	}
	m := mbpsRe.FindStringSubmatch(s)
	if m == nil {
		return iOf(v)
	}
	f, _ := strconv.ParseFloat(m[1], 64)
	switch strings.ToLower(m[2]) {
	case "k":
		f /= 1000
	case "g":
		f *= 1000
	}
	return int(f)
}

func normNet(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "raw":
		return "tcp"
	case "splithttp":
		return "xhttp"
	case "mkcp":
		return "kcp"
	}
	return s
}

func xrayToNode(ob map[string]any, name string) *Node {
	proto := strings.ToLower(sOf(ob["protocol"]))
	set := mOf(ob["settings"])
	if set == nil {
		set = map[string]any{}
	}
	first := func(key string) map[string]any {
		if a := lOf(set[key]); len(a) > 0 {
			return mOf(a[0])
		}
		return nil
	}
	n := &Node{Name: name}
	switch proto {
	case "vless", "vmess":
		n.Proto = proto
		var u map[string]any
		if srv := first("vnext"); srv != nil {
			n.Host, n.Port = sOf(srv["address"]), iOf(srv["port"])
			if us := lOf(srv["users"]); len(us) > 0 {
				u = mOf(us[0])
			}
		} else {
			n.Host, n.Port, u = sOf(set["address"]), iOf(set["port"]), set
		}
		if u == nil {
			return nil
		}
		n.UUID = sOf(u["id"])
		if proto == "vless" {
			n.Flow = sOf(u["flow"])
			if e := sOf(u["encryption"]); e != "" && e != "none" {
				n.Encryption = e
			}
		} else {
			n.AlterID = iOf(u["alterId"])
			n.VmessSec = sOf(u["security"])
			if n.VmessSec == "" {
				n.VmessSec = "auto"
			}
		}
	case "trojan", "shadowsocks":
		srv := first("servers")
		if srv == nil {
			srv = set
		}
		n.Host, n.Port, n.Password = sOf(srv["address"]), iOf(srv["port"]), sOf(srv["password"])
		n.Proto = "trojan"
		if proto == "shadowsocks" {
			n.Proto, n.Method = "ss", strings.ToLower(sOf(srv["method"]))
		}
	case "socks":
		srv := first("servers")
		if srv == nil {
			srv = set
		}
		n.Proto, n.Host, n.Port = "socks", sOf(srv["address"]), iOf(srv["port"])
		if us := lOf(srv["users"]); len(us) > 0 {
			u := mOf(us[0])
			n.User, n.Password = sOf(u["user"]), sOf(u["pass"])
		}
	case "wireguard":
		n.Proto = "wireguard"
		n.PrivKey = sOf(set["secretKey"])
		n.Address = strList(set["address"])
		n.MTU = iOf(set["mtu"])
		n.Reserved = intList(set["reserved"])
		if ps := lOf(set["peers"]); len(ps) > 0 {
			p := mOf(ps[0])
			n.PubKey, n.PSK = sOf(p["publicKey"]), sOf(p["preSharedKey"])
			ep := sOf(p["endpoint"])
			if i := strings.LastIndex(ep, ":"); i > 0 {
				n.Host = strings.Trim(ep[:i], "[]")
				n.Port, _ = strconv.Atoi(ep[i+1:])
			}
		}
		return n
	case "hysteria":
		ss := mOf(ob["streamSettings"])
		hs := mOf(ss["hysteriaSettings"])
		if iOf(set["version"]) != 2 && iOf(hs["version"]) != 2 {
			return nil
		}
		n.Proto, n.Host, n.Port, n.Security = "hysteria2", sOf(set["address"]), iOf(set["port"]), "tls"
		n.Password = sOf(hs["auth"])
		if t := mOf(ss["tlsSettings"]); t != nil {
			n.SNI, n.Insecure, n.ALPN = sOf(t["serverName"]), bOf(t["allowInsecure"]), strList(t["alpn"])
		}
		return n
	default:
		return nil
	}
	ss := mOf(ob["streamSettings"])
	if ss == nil {
		ss = map[string]any{}
	}
	n.Net = normNet(sOf(ss["network"]))
	n.Security = strings.ToLower(sOf(ss["security"]))
	if n.Security == "" || n.Security == "xtls" {
		if n.Security == "xtls" {
			n.Security = "tls"
		} else {
			n.Security = "none"
		}
	}
	if t := mOf(ss["tlsSettings"]); t != nil && n.Security == "tls" {
		n.SNI, n.Insecure, n.FP = sOf(t["serverName"]), bOf(t["allowInsecure"]), sOf(t["fingerprint"])
		n.ALPN = strList(t["alpn"])
	}
	if r := mOf(ss["realitySettings"]); r != nil && n.Security == "reality" {
		n.SNI, n.FP, n.SID, n.SPX = sOf(r["serverName"]), sOf(r["fingerprint"]), sOf(r["shortId"]), sOf(r["spiderX"])
		n.PQV = sOf(r["mldsa65Verify"])
		n.PBK = sOf(r["publicKey"])
		if n.PBK == "" {
			n.PBK = sOf(r["password"])
		}
	}
	switch n.Net {
	case "ws":
		w := mOf(ss["wsSettings"])
		n.Path, n.HostHdr = sOf(w["path"]), sOf(w["host"])
		if n.HostHdr == "" {
			n.HostHdr = hdrHost(w["headers"])
		}
	case "httpupgrade":
		w := mOf(ss["httpupgradeSettings"])
		n.Path, n.HostHdr = sOf(w["path"]), sOf(w["host"])
	case "grpc":
		g := mOf(ss["grpcSettings"])
		n.ServiceName, n.Authority = sOf(g["serviceName"]), sOf(g["authority"])
		if bOf(g["multiMode"]) {
			n.Mode = "multi"
		}
	case "xhttp":
		x := mOf(ss["xhttpSettings"])
		if x == nil {
			x = mOf(ss["splithttpSettings"])
		}
		n.Path, n.HostHdr, n.Mode = sOf(x["path"]), sOf(x["host"]), sOf(x["mode"])
		if e := mOf(x["extra"]); len(e) > 0 {
			b, _ := json.Marshal(e)
			n.Extra = string(b)
		}
	case "kcp":
		k := mOf(ss["kcpSettings"])
		n.HeaderType, n.Seed = sOf(mOf(k["header"])["type"]), sOf(k["seed"])
	case "http", "h2":
		h := mOf(ss["httpSettings"])
		n.Path, n.HostHdr = sOf(h["path"]), sOf(h["host"])
	case "tcp":
		t := mOf(ss["tcpSettings"])
		if t == nil {
			t = mOf(ss["rawSettings"])
		}
		hd := mOf(t["header"])
		if strings.EqualFold(sOf(hd["type"]), "http") {
			n.HeaderType = "http"
			req := mOf(hd["request"])
			n.Path = sOf(req["path"])
			n.HostHdr = hdrHost(req["headers"])
		}
	}
	return n
}

func singboxToNode(o map[string]any) *Node {
	t := strings.ToLower(sOf(o["type"]))
	n := &Node{Name: sOf(o["tag"]), Host: sOf(o["server"]), Port: iOf(o["server_port"]), Net: "tcp", Security: "none"}
	if tl := mOf(o["tls"]); tl != nil && bOf(tl["enabled"]) {
		n.Security = "tls"
		n.SNI, n.Insecure, n.ALPN = sOf(tl["server_name"]), bOf(tl["insecure"]), strList(tl["alpn"])
		if u := mOf(tl["utls"]); u != nil && bOf(u["enabled"]) {
			n.FP = sOf(u["fingerprint"])
		}
		if r := mOf(tl["reality"]); r != nil && bOf(r["enabled"]) {
			n.Security, n.PBK, n.SID = "reality", sOf(r["public_key"]), sOf(r["short_id"])
		}
	}
	if tr := mOf(o["transport"]); tr != nil {
		switch strings.ToLower(sOf(tr["type"])) {
		case "ws":
			n.Net, n.Path, n.HostHdr = "ws", sOf(tr["path"]), hdrHost(tr["headers"])
			if ed := iOf(tr["max_early_data"]); ed > 0 && !strings.Contains(n.Path, "ed=") {
				sep := "?"
				if strings.Contains(n.Path, "?") {
					sep = "&"
				}
				n.Path += sep + "ed=" + strconv.Itoa(ed)
			}
		case "grpc":
			n.Net, n.ServiceName = "grpc", sOf(tr["service_name"])
		case "http":
			n.Net, n.Path, n.HostHdr = "http", sOf(tr["path"]), sOf(tr["host"])
		case "httpupgrade":
			n.Net, n.Path, n.HostHdr = "httpupgrade", sOf(tr["path"]), sOf(tr["host"])
		case "quic":
			n.Net = "quic"
		}
	}
	switch t {
	case "vless":
		n.Proto, n.UUID, n.Flow = "vless", sOf(o["uuid"]), sOf(o["flow"])
	case "vmess":
		n.Proto, n.UUID, n.VmessSec, n.AlterID = "vmess", sOf(o["uuid"]), sOf(o["security"]), iOf(o["alter_id"])
		if n.VmessSec == "" {
			n.VmessSec = "auto"
		}
	case "trojan":
		n.Proto, n.Password = "trojan", sOf(o["password"])
	case "shadowsocks":
		n.Proto, n.Method, n.Password = "ss", strings.ToLower(sOf(o["method"])), sOf(o["password"])
		n.Plugin, n.PluginOpts = sOf(o["plugin"]), sOf(o["plugin_opts"])
	case "hysteria2":
		n.Proto, n.Password = "hysteria2", sOf(o["password"])
		var hops []string
		for _, p := range strList(o["server_ports"]) {
			hops = append(hops, strings.ReplaceAll(p, ":", "-"))
		}
		n.Ports = strings.Join(hops, ",")
		if ob := mOf(o["obfs"]); ob != nil {
			n.Obfs, n.ObfsPassword = sOf(ob["type"]), sOf(ob["password"])
		}
		n.UpMbps, n.DownMbps = iOf(o["up_mbps"]), iOf(o["down_mbps"])
		n.Security = "tls"
	case "hysteria":
		n.Proto, n.Password, n.ObfsPassword = "hysteria", sOf(o["auth_str"]), sOf(o["obfs"])
		n.UpMbps, n.DownMbps = iOf(o["up_mbps"]), iOf(o["down_mbps"])
		n.Security = "tls"
	case "tuic":
		n.Proto, n.UUID, n.Password = "tuic", sOf(o["uuid"]), sOf(o["password"])
		n.CC, n.UDPRelay = sOf(o["congestion_control"]), sOf(o["udp_relay_mode"])
		n.Security = "tls"
	case "socks":
		n.Proto, n.User, n.Password = "socks", sOf(o["username"]), sOf(o["password"])
	case "anytls":
		n.Proto, n.Password, n.Security = "anytls", sOf(o["password"]), "tls"
	case "naive":
		n.Proto, n.User, n.Password, n.Security = "naive", sOf(o["username"]), sOf(o["password"]), "tls"
		if bOf(o["quic"]) {
			n.Net = "quic"
		}
	case "wireguard":
		n.Proto = "wireguard"
		n.PrivKey, n.MTU = sOf(o["private_key"]), iOf(o["mtu"])
		n.Address = strList(o["local_address"])
		if len(n.Address) == 0 {
			n.Address = strList(o["address"])
		}
		n.PubKey, n.PSK, n.Reserved = sOf(o["peer_public_key"]), sOf(o["pre_shared_key"]), intList(o["reserved"])
		if ps := lOf(o["peers"]); len(ps) > 0 {
			p := mOf(ps[0])
			n.Host, n.Port = sOf(p["address"]), iOf(p["port"])
			n.PubKey, n.PSK, n.Reserved = sOf(p["public_key"]), sOf(p["pre_shared_key"]), intList(p["reserved"])
		}
	default:
		return nil
	}
	return n
}

func clashToNode(p map[string]any) *Node {
	t := strings.ToLower(sOf(p["type"]))
	n := &Node{Name: sOf(p["name"]), Host: sOf(p["server"]), Port: iOf(p["port"]), Net: "tcp", Security: "none"}
	sni := sOf(p["servername"])
	if sni == "" {
		sni = sOf(p["sni"])
	}
	n.SNI, n.Insecure, n.FP, n.ALPN = sni, bOf(p["skip-cert-verify"]), sOf(p["client-fingerprint"]), strList(p["alpn"])
	if bOf(p["tls"]) {
		n.Security = "tls"
	}
	if ro := mOf(p["reality-opts"]); ro != nil {
		n.Security, n.PBK, n.SID = "reality", sOf(ro["public-key"]), sOf(ro["short-id"])
	}
	switch strings.ToLower(sOf(p["network"])) {
	case "ws":
		w := mOf(p["ws-opts"])
		n.Net, n.Path, n.HostHdr = "ws", sOf(w["path"]), hdrHost(w["headers"])
		if ed := iOf(w["max-early-data"]); ed > 0 && !strings.Contains(n.Path, "ed=") {
			n.Path += "?ed=" + strconv.Itoa(ed)
		}
		if bOf(w["v2ray-http-upgrade"]) {
			n.Net = "httpupgrade"
		}
	case "grpc":
		n.Net, n.ServiceName = "grpc", sOf(mOf(p["grpc-opts"])["grpc-service-name"])
	case "h2":
		h := mOf(p["h2-opts"])
		n.Net, n.Path, n.HostHdr = "http", sOf(h["path"]), sOf(h["host"])
	case "http":
		h := mOf(p["http-opts"])
		n.Net, n.HeaderType, n.Path, n.HostHdr = "tcp", "http", sOf(h["path"]), hdrHost(h["headers"])
	case "xhttp":
		x := mOf(p["xhttp-opts"])
		n.Net, n.Path, n.HostHdr, n.Mode = "xhttp", sOf(x["path"]), sOf(x["host"]), sOf(x["mode"])
	}
	switch t {
	case "vless":
		n.Proto, n.UUID, n.Flow = "vless", sOf(p["uuid"]), sOf(p["flow"])
		if e := sOf(p["encryption"]); e != "" && e != "none" {
			n.Encryption = e
		}
	case "vmess":
		n.Proto, n.UUID, n.AlterID, n.VmessSec = "vmess", sOf(p["uuid"]), iOf(p["alterId"]), sOf(p["cipher"])
		if n.VmessSec == "" {
			n.VmessSec = "auto"
		}
	case "trojan":
		n.Proto, n.Password = "trojan", sOf(p["password"])
		if n.Security == "none" {
			n.Security = "tls"
		}
	case "ss":
		n.Proto, n.Method, n.Password = "ss", strings.ToLower(sOf(p["cipher"])), sOf(p["password"])
		if pl := sOf(p["plugin"]); pl != "" {
			po := mOf(p["plugin-opts"])
			switch pl {
			case "obfs":
				n.Plugin = "obfs-local"
				n.PluginOpts = "obfs=" + sOf(po["mode"])
				if h := sOf(po["host"]); h != "" {
					n.PluginOpts += ";obfs-host=" + h
				}
			case "v2ray-plugin":
				n.Plugin = "v2ray-plugin"
				opts := []string{"mode=" + sOf(po["mode"])}
				if h := sOf(po["host"]); h != "" {
					opts = append(opts, "host="+h)
				}
				if pa := sOf(po["path"]); pa != "" {
					opts = append(opts, "path="+pa)
				}
				if bOf(po["tls"]) {
					opts = append(opts, "tls")
				}
				n.PluginOpts = strings.Join(opts, ";")
			}
		}
	case "hysteria2":
		n.Proto, n.Password, n.Security = "hysteria2", sOf(p["password"]), "tls"
		if n.Password == "" {
			n.Password = sOf(p["auth"])
		}
		n.Ports = strings.ReplaceAll(sOf(p["ports"]), "/", ",")
		n.Obfs, n.ObfsPassword = sOf(p["obfs"]), sOf(p["obfs-password"])
		n.UpMbps, n.DownMbps = mbps(p["up"]), mbps(p["down"])
	case "hysteria":
		n.Proto, n.Security = "hysteria", "tls"
		n.Password = sOf(p["auth-str"])
		if n.Password == "" {
			n.Password = sOf(p["auth_str"])
		}
		n.ObfsPassword = sOf(p["obfs"])
		n.UpMbps, n.DownMbps = mbps(p["up"]), mbps(p["down"])
	case "tuic":
		n.Proto, n.UUID, n.Password, n.Security = "tuic", sOf(p["uuid"]), sOf(p["password"]), "tls"
		n.CC, n.UDPRelay = sOf(p["congestion-controller"]), sOf(p["udp-relay-mode"])
	case "wireguard":
		n.Proto = "wireguard"
		n.PrivKey, n.PubKey, n.PSK = sOf(p["private-key"]), sOf(p["public-key"]), sOf(p["pre-shared-key"])
		n.MTU, n.Reserved = iOf(p["mtu"]), intList(p["reserved"])
		for _, k := range []string{"ip", "ipv6"} {
			if a := sOf(p[k]); a != "" {
				n.Address = append(n.Address, a)
			}
		}
		if ps := lOf(p["peers"]); len(ps) > 0 {
			pp := mOf(ps[0])
			if n.Host == "" {
				n.Host, n.Port = sOf(pp["server"]), iOf(pp["port"])
			}
			if n.PubKey == "" {
				n.PubKey, n.PSK = sOf(pp["public-key"]), sOf(pp["pre-shared-key"])
			}
			if len(n.Reserved) == 0 {
				n.Reserved = intList(pp["reserved"])
			}
		}
	case "socks5":
		n.Proto, n.User, n.Password = "socks", sOf(p["username"]), sOf(p["password"])
	case "anytls":
		n.Proto, n.Password, n.Security = "anytls", sOf(p["password"]), "tls"
	default:
		return nil
	}
	return n
}

func qesc(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }

func hostPort(h string, p int) string {
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return h + ":" + strconv.Itoa(p)
}

func (n *Node) ShareLink() string {
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	tlsQ := func() {
		set("sni", n.SNI)
		set("alpn", strings.Join(n.ALPN, ","))
		if n.Insecure {
			q.Set("insecure", "1")
			q.Set("allowInsecure", "1")
		}
	}
	frag := "#" + qesc(n.Name)
	hp := hostPort(n.Host, n.Port)
	qs := func() string {
		if len(q) == 0 {
			return ""
		}
		return "?" + q.Encode()
	}
	switch n.Proto {
	case "vless", "trojan":
		set("type", n.Net)
		set("security", n.Security)
		tlsQ()
		set("fp", n.FP)
		set("pbk", n.PBK)
		set("sid", n.SID)
		set("spx", n.SPX)
		set("pqv", n.PQV)
		set("host", n.HostHdr)
		set("path", n.Path)
		set("serviceName", n.ServiceName)
		set("headerType", n.HeaderType)
		set("mode", n.Mode)
		set("extra", n.Extra)
		set("seed", n.Seed)
		set("authority", n.Authority)
		user := n.Password
		if n.Proto == "vless" {
			user = n.UUID
			set("flow", n.Flow)
			if n.Encryption != "" {
				q.Set("encryption", n.Encryption)
			} else {
				q.Set("encryption", "none")
			}
		}
		return n.Proto + "://" + qesc(user) + "@" + hp + qs() + frag
	case "vmess":
		if n.Extra != "" || n.Authority != "" {
			set("type", n.Net)
			set("security", n.Security)
			tlsQ()
			set("fp", n.FP)
			set("pbk", n.PBK)
			set("sid", n.SID)
			set("host", n.HostHdr)
			set("path", n.Path)
			set("serviceName", n.ServiceName)
			set("headerType", n.HeaderType)
			set("mode", n.Mode)
			set("extra", n.Extra)
			set("seed", n.Seed)
			set("authority", n.Authority)
			set("encryption", n.VmessSec)
			return "vmess://" + qesc(n.UUID) + "@" + hp + qs() + frag
		}
		sec := ""
		if n.Security == "tls" || n.Security == "reality" {
			sec = n.Security
		}
		m := map[string]string{"v": "2", "ps": n.Name, "add": n.Host, "port": strconv.Itoa(n.Port), "id": n.UUID,
			"aid": strconv.Itoa(n.AlterID), "scy": n.VmessSec, "net": n.Net, "type": n.HeaderType, "host": n.HostHdr,
			"path": n.Path, "tls": sec, "sni": n.SNI, "alpn": strings.Join(n.ALPN, ","), "fp": n.FP, "pbk": n.PBK, "sid": n.SID}
		switch n.Net {
		case "grpc":
			m["path"] = n.ServiceName
			m["type"] = n.Mode
		case "xhttp":
			m["type"] = n.Mode
		case "kcp":
			m["path"] = n.Seed
		}
		if n.Insecure {
			m["allowInsecure"] = "1"
		}
		b, _ := json.Marshal(m)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	case "ss":
		l := "ss://" + base64.RawURLEncoding.EncodeToString([]byte(n.Method+":"+n.Password)) + "@" + hp
		if n.Plugin != "" {
			pl := n.Plugin
			if n.PluginOpts != "" {
				pl += ";" + n.PluginOpts
			}
			l += "/?plugin=" + qesc(pl)
		}
		return l + frag
	case "hysteria2":
		tlsQ()
		set("obfs", n.Obfs)
		set("obfs-password", n.ObfsPassword)
		set("mport", n.Ports)
		if n.UpMbps > 0 {
			q.Set("upmbps", strconv.Itoa(n.UpMbps))
		}
		if n.DownMbps > 0 {
			q.Set("downmbps", strconv.Itoa(n.DownMbps))
		}
		return "hysteria2://" + qesc(n.Password) + "@" + hp + "/" + qs() + frag
	case "hysteria":
		set("auth", n.Password)
		set("peer", n.SNI)
		set("alpn", strings.Join(n.ALPN, ","))
		if n.Insecure {
			q.Set("insecure", "1")
		}
		set("obfsParam", n.ObfsPassword)
		if n.UpMbps > 0 {
			q.Set("upmbps", strconv.Itoa(n.UpMbps))
		}
		if n.DownMbps > 0 {
			q.Set("downmbps", strconv.Itoa(n.DownMbps))
		}
		return "hysteria://" + hp + qs() + frag
	case "tuic":
		set("sni", n.SNI)
		set("alpn", strings.Join(n.ALPN, ","))
		if n.Insecure {
			q.Set("allow_insecure", "1")
		}
		set("congestion_control", n.CC)
		set("udp_relay_mode", n.UDPRelay)
		return "tuic://" + qesc(n.UUID) + ":" + qesc(n.Password) + "@" + hp + qs() + frag
	case "wireguard":
		set("publickey", n.PubKey)
		set("presharedkey", n.PSK)
		set("address", strings.Join(n.Address, ","))
		if n.MTU > 0 {
			q.Set("mtu", strconv.Itoa(n.MTU))
		}
		if len(n.Reserved) > 0 {
			var r []string
			for _, v := range n.Reserved {
				r = append(r, strconv.Itoa(v))
			}
			q.Set("reserved", strings.Join(r, ","))
		}
		return "wireguard://" + qesc(n.PrivKey) + "@" + hp + qs() + frag
	case "socks":
		ui := ""
		if n.User != "" || n.Password != "" {
			ui = qesc(n.User) + ":" + qesc(n.Password) + "@"
		}
		return "socks://" + ui + hp + frag
	case "anytls":
		tlsQ()
		set("fp", n.FP)
		return "anytls://" + qesc(n.Password) + "@" + hp + qs() + frag
	case "naive":
		scheme := "naive+https"
		if n.Net == "quic" {
			scheme = "naive+quic"
		}
		set("sni", n.SNI)
		ui := ""
		if n.User != "" || n.Password != "" {
			ui = qesc(n.User) + ":" + qesc(n.Password) + "@"
		}
		return scheme + "://" + ui + hp + qs() + frag
	}
	return ""
}

const (
	fmtLinks   = "ссылки"
	fmtXray    = "Xray JSON"
	fmtSingbox = "sing-box JSON"
	fmtClash   = "Clash/Mihomo YAML"
	fmtHTML    = "HTML-страница"
	fmtHapp    = "зашифровано для Happ"
	fmtEmpty   = "пустой ответ"
	fmtUnknown = "неизвестный формат"
)

func isProxyOutboundXray(p string) bool {
	switch strings.ToLower(p) {
	case "vless", "vmess", "trojan", "shadowsocks", "socks", "wireguard", "hysteria":
		return true
	}
	return false
}

func nodesFromJSON(v any) (nodes []*Node, format string) {
	addXrayConfig := func(cfg map[string]any) {
		remarks := sOf(cfg["remarks"])
		var proxies []map[string]any
		for _, o := range lOf(cfg["outbounds"]) {
			ob := mOf(o)
			if ob != nil && isProxyOutboundXray(sOf(ob["protocol"])) {
				proxies = append(proxies, ob)
			}
		}
		if len(proxies) > 1 {
			for _, ob := range proxies {
				if sOf(ob["tag"]) == "proxy" {
					proxies = []map[string]any{ob}
					break
				}
			}
		}
		for _, ob := range proxies {
			name := remarks
			if name == "" || len(proxies) > 1 {
				if t := sOf(ob["tag"]); t != "" && t != "proxy" {
					name = strings.TrimSpace(remarks + " " + t)
				}
			}
			if n := xrayToNode(ob, name); n != nil {
				nodes = append(nodes, n)
			}
		}
	}
	addSingbox := func(list []any) {
		for _, o := range list {
			if ob := mOf(o); ob != nil {
				if n := singboxToNode(ob); n != nil {
					nodes = append(nodes, n)
				}
			}
		}
	}
	handle := func(m map[string]any) {
		switch {
		case m == nil:
		case m["outbounds"] != nil || m["endpoints"] != nil:
			outs := lOf(m["outbounds"])
			isXray := false
			for _, o := range outs {
				if mOf(o)["protocol"] != nil {
					isXray = true
					break
				}
			}
			if isXray {
				format = fmtXray
				addXrayConfig(m)
			} else {
				format = fmtSingbox
				addSingbox(outs)
				addSingbox(lOf(m["endpoints"]))
			}
		case m["proxies"] != nil:
			format = fmtClash
			for _, p := range lOf(m["proxies"]) {
				if n := clashToNode(mOf(p)); n != nil {
					nodes = append(nodes, n)
				}
			}
		case m["protocol"] != nil:
			format = fmtXray
			if n := xrayToNode(m, sOf(m["tag"])); n != nil {
				nodes = append(nodes, n)
			}
		case m["type"] != nil && m["server"] != nil:
			format = fmtSingbox
			if n := singboxToNode(m); n != nil {
				nodes = append(nodes, n)
			}
		}
	}
	if arr := lOf(v); arr != nil {
		for _, x := range arr {
			handle(mOf(x))
		}
	} else {
		handle(mOf(v))
	}
	return
}

func ParseSubscriptionBody(body []byte) (nodes []*Node, format string) {
	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
	if text == "" {
		return nil, fmtEmpty
	}
	if !strings.Contains(text, "://") && !strings.ContainsAny(text, "{[") {
		if b, err := b64decode(text); err == nil && len(b) > 0 {
			text = strings.TrimSpace(string(b))
		}
	}
	head := strings.ToLower(text[:min(len(text), 512)])
	if strings.HasPrefix(head, "<!doctype") || strings.HasPrefix(head, "<html") || strings.Contains(head, "<head") || strings.Contains(head, "<body") {
		return nil, fmtHTML
	}
	var raw []*Node
	switch {
	case strings.HasPrefix(text, "{") || strings.HasPrefix(text, "["):
		var v any
		if err := json.Unmarshal([]byte(text), &v); err == nil {
			raw, format = nodesFromJSON(v)
		}
	case regexp.MustCompile(`(?m)^proxies\s*:`).MatchString(text):
		var v map[string]any
		if err := yaml.Unmarshal([]byte(text), &v); err == nil {
			raw, format = nodesFromJSON(v)
		}
		format = fmtClash
	}
	if format != "" {
		seen := map[string]bool{}
		for _, n := range raw {
			if n.Host == "" || n.Port == 0 {
				continue
			}
			link := n.ShareLink()
			if link == "" || seen[link] {
				continue
			}
			if p, err := ParseLink(link); err == nil {
				seen[link] = true
				nodes = append(nodes, p)
			}
		}
		return nodes, format
	}
	crypt := false
	for _, l := range SplitInput(text) {
		if strings.HasPrefix(strings.ToLower(l), "happ://") {
			crypt = true
			continue
		}
		if n, err := ParseLink(l); err == nil {
			nodes = append(nodes, n)
		}
	}
	switch {
	case len(nodes) > 0:
		return nodes, fmtLinks
	case crypt:
		return nil, fmtHapp
	}
	return nil, fmtUnknown
}
