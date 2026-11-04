package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

type M = map[string]any

var utlsFP = map[string]bool{"chrome": true, "firefox": true, "edge": true, "safari": true, "360": true, "qq": true, "ios": true, "android": true, "random": true, "randomized": true}

func normFP(fp string) string {
	fp = strings.ToLower(strings.TrimSpace(fp))
	if fp == "" || fp == "none" {
		return ""
	}
	if utlsFP[fp] {
		return fp
	}
	if strings.HasPrefix(fp, "chrome") {
		return "chrome"
	}
	if strings.HasPrefix(fp, "firefox") {
		return "firefox"
	}
	return "chrome"
}

func isIP(h string) bool { return net.ParseIP(h) != nil }

func defaultSNI(n *Node) string {
	if n.SNI != "" {
		return n.SNI
	}
	if n.HostHdr != "" && (n.Net == "ws" || n.Net == "httpupgrade" || n.Net == "http" || n.Net == "h2") {
		return strings.Split(n.HostHdr, ",")[0]
	}
	if !isIP(n.Host) {
		return n.Host
	}
	return ""
}

func sbTLS(n *Node, defALPN []string) M {
	if n.Security != "tls" && n.Security != "reality" {
		return nil
	}
	t := M{"enabled": true}
	if sni := defaultSNI(n); sni != "" {
		t["server_name"] = sni
	}
	if n.Insecure {
		t["insecure"] = true
	}
	if len(n.ALPN) > 0 {
		t["alpn"] = n.ALPN
	} else if len(defALPN) > 0 {
		t["alpn"] = defALPN
	}
	fp := normFP(n.FP)
	if n.Security == "reality" {
		if fp == "" {
			fp = "chrome"
		}
		r := M{"enabled": true, "public_key": n.PBK}
		if n.SID != "" {
			r["short_id"] = n.SID
		}
		t["reality"] = r
	}
	if fp != "" {
		t["utls"] = M{"enabled": true, "fingerprint": fp}
	}
	return t
}

func splitEarlyData(p string) (string, int) {
	if p == "" {
		return "/", 0
	}
	u, err := url.Parse(p)
	if err != nil {
		return p, 0
	}
	q := u.Query()
	ed, _ := strconv.Atoi(q.Get("ed"))
	if ed > 0 {
		q.Del("ed")
		u.RawQuery = q.Encode()
		s := u.String()
		if s == "" {
			s = "/"
		}
		return s, ed
	}
	return p, 0
}

func sbTransport(n *Node) M {
	switch n.Net {
	case "ws":
		path, ed := splitEarlyData(n.Path)
		m := M{"type": "ws", "path": path}
		if n.HostHdr != "" {
			m["headers"] = M{"Host": n.HostHdr}
		}
		if ed > 0 {
			m["max_early_data"] = ed
			m["early_data_header_name"] = "Sec-WebSocket-Protocol"
		}
		return m
	case "grpc":
		return M{"type": "grpc", "service_name": n.ServiceName}
	case "http", "h2":
		m := M{"type": "http"}
		if h := splitList(n.HostHdr); len(h) > 0 {
			m["host"] = h
		}
		if n.Path != "" {
			m["path"] = n.Path
		}
		return m
	case "httpupgrade":
		m := M{"type": "httpupgrade", "path": n.Path}
		if n.Path == "" {
			m["path"] = "/"
		}
		if n.HostHdr != "" {
			m["host"] = n.HostHdr
		}
		return m
	}
	return nil
}

func ssMethod(m string) string {
	switch m {
	case "chacha20-poly1305":
		return "chacha20-ietf-poly1305"
	case "xchacha20-poly1305":
		return "xchacha20-ietf-poly1305"
	}
	return m
}

func hopPorts(s string) []string {
	var out []string
	for _, p := range splitList(s) {
		p = strings.ReplaceAll(p, "-", ":")
		if !strings.Contains(p, ":") {
			p = p + ":" + p
		}
		out = append(out, p)
	}
	return out
}

func SingboxOutbound(n *Node, tag string) (out M, isEndpoint bool, err error) {
	base := func(t string) M { return M{"type": t, "tag": tag, "server": n.Host, "server_port": n.Port} }
	switch n.Proto {
	case "vless":
		o := base("vless")
		o["uuid"] = n.UUID
		if strings.HasPrefix(n.Flow, "xtls-rprx-vision") {
			o["flow"] = "xtls-rprx-vision"
		}
		o["packet_encoding"] = "xudp"
		if t := sbTLS(n, nil); t != nil {
			o["tls"] = t
		}
		if tr := sbTransport(n); tr != nil {
			o["transport"] = tr
		}
		return o, false, nil
	case "vmess":
		o := base("vmess")
		o["uuid"] = n.UUID
		sec := strings.ToLower(n.VmessSec)
		switch sec {
		case "", "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305", "aes-128-ctr":
		default:
			sec = "auto"
		}
		if sec == "" {
			sec = "auto"
		}
		o["security"] = sec
		if n.AlterID > 0 {
			o["alter_id"] = n.AlterID
		}
		if t := sbTLS(n, nil); t != nil {
			o["tls"] = t
		}
		if tr := sbTransport(n); tr != nil {
			o["transport"] = tr
		}
		return o, false, nil
	case "trojan":
		o := base("trojan")
		o["password"] = n.Password
		if t := sbTLS(n, nil); t != nil {
			o["tls"] = t
		}
		if tr := sbTransport(n); tr != nil {
			o["transport"] = tr
		}
		return o, false, nil
	case "ss":
		o := base("shadowsocks")
		o["method"] = ssMethod(n.Method)
		o["password"] = n.Password
		if n.Plugin != "" {
			o["plugin"] = n.Plugin
			o["plugin_opts"] = n.PluginOpts
		}
		return o, false, nil
	case "hysteria2":
		o := base("hysteria2")
		o["password"] = n.Password
		if n.Ports != "" {
			o["server_ports"] = hopPorts(n.Ports)
		}
		if n.Obfs != "" && n.Obfs != "none" {
			o["obfs"] = M{"type": n.Obfs, "password": n.ObfsPassword}
		}
		if n.UpMbps > 0 {
			o["up_mbps"] = n.UpMbps
		}
		if n.DownMbps > 0 {
			o["down_mbps"] = n.DownMbps
		}
		nn := *n
		nn.Security = "tls"
		nn.FP = ""
		o["tls"] = sbTLS(&nn, []string{"h3"})
		return o, false, nil
	case "hysteria":
		o := base("hysteria")
		o["up_mbps"] = n.UpMbps
		o["down_mbps"] = n.DownMbps
		if n.Password != "" {
			o["auth_str"] = n.Password
		}
		if n.ObfsPassword != "" {
			o["obfs"] = n.ObfsPassword
		}
		nn := *n
		nn.Security = "tls"
		nn.FP = ""
		o["tls"] = sbTLS(&nn, []string{"hysteria"})
		return o, false, nil
	case "tuic":
		o := base("tuic")
		o["uuid"] = n.UUID
		o["password"] = n.Password
		cc := n.CC
		if cc == "" {
			cc = "bbr"
		}
		o["congestion_control"] = cc
		if n.UDPRelay != "" {
			o["udp_relay_mode"] = n.UDPRelay
		}
		nn := *n
		nn.Security = "tls"
		nn.FP = ""
		o["tls"] = sbTLS(&nn, []string{"h3"})
		return o, false, nil
	case "anytls":
		o := base("anytls")
		o["password"] = n.Password
		nn := *n
		nn.Security = "tls"
		o["tls"] = sbTLS(&nn, nil)
		return o, false, nil
	case "naive":
		o := base("naive")
		o["username"] = n.User
		o["password"] = n.Password
		if n.Net == "quic" {
			o["quic"] = true
		}
		nn := *n
		nn.Security = "tls"
		nn.FP = ""
		nn.ALPN = nil
		o["tls"] = sbTLS(&nn, nil)
		return o, false, nil
	case "socks":
		o := base("socks")
		o["version"] = "5"
		if n.User != "" {
			o["username"] = n.User
			o["password"] = n.Password
		}
		return o, false, nil
	case "wireguard":
		mtu := n.MTU
		if mtu == 0 {
			mtu = 1408
		}
		peer := M{"address": n.Host, "port": n.Port, "public_key": n.PubKey, "allowed_ips": []string{"0.0.0.0/0", "::/0"}}
		if n.PSK != "" {
			peer["pre_shared_key"] = n.PSK
		}
		if len(n.Reserved) == 3 {
			peer["reserved"] = n.Reserved
		}
		return M{"type": "wireguard", "tag": tag, "address": n.Address, "private_key": n.PrivKey, "mtu": mtu, "peers": []M{peer}}, true, nil
	}
	return nil, false, fmt.Errorf("протокол %s не поддерживается ядром sing-box", n.Proto)
}

func dnsServer(tag, spec, detour string) M {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "local" || spec == "system" {
		return localDNS(tag)
	}
	typ := "udp"
	rest := spec
	if i := strings.Index(spec, "://"); i >= 0 {
		typ = strings.ToLower(spec[:i])
		rest = spec[i+3:]
	}
	switch typ {
	case "doh":
		typ = "https"
	case "dot":
		typ = "tls"
	case "doq":
		typ = "quic"
	}
	path := ""
	if i := strings.Index(rest, "/"); i >= 0 {
		path = rest[i:]
		rest = rest[:i]
	}
	host, port := rest, ""
	if h, p, err := net.SplitHostPort(rest); err == nil {
		host, port = h, p
	}
	host = strings.Trim(host, "[]")
	m := M{"type": typ, "tag": tag, "server": host}
	if port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			m["server_port"] = p
		}
	}
	if (typ == "https" || typ == "h3") && path != "" && path != "/dns-query" {
		m["path"] = path
	}
	if detour != "" {
		m["detour"] = detour
	}
	if !isIP(host) {
		m["domain_resolver"] = "dns-local"
	}
	return m
}

func clashAPI(rp RunPorts) M {
	return M{"external_controller": fmt.Sprintf("127.0.0.1:%d", rp.Clash), "secret": rp.Secret,
		"access_control_allow_origin": []string{"https://volfram.invalid"}}
}

type RunPorts struct {
	Mixed        int
	Clash        int
	Xray         int
	Secret       string
	User, Pass   string
	XUser, XPass string
}

func xraySocks(user, pass string) M {
	if user == "" {
		return M{"udp": true, "auth": "noauth"}
	}
	return M{"udp": true, "auth": "password", "accounts": []M{{"user": user, "pass": pass}}}
}

type domainRule struct {
	suffix, keyword, cidr []string
}

func parseDomainList(list []string) domainRule {
	var r domainRule
	for _, raw := range list {
		for _, d := range strings.FieldsFunc(raw, func(c rune) bool { return c == '\n' || c == ',' || c == ' ' || c == ';' }) {
			d = strings.TrimSpace(strings.ToLower(d))
			if d == "" || strings.HasPrefix(d, "#") {
				continue
			}
			if !strings.HasPrefix(d, "keyword:") {
				d = cleanRuleEntry(d)
			}
			switch {
			case strings.HasPrefix(d, "keyword:"):
				r.keyword = append(r.keyword, strings.TrimPrefix(d, "keyword:"))
			case strings.Contains(d, "/"):
				if _, _, err := net.ParseCIDR(d); err == nil {
					r.cidr = append(r.cidr, d)
				}
			case isIP(d):
				if strings.Contains(d, ":") {
					r.cidr = append(r.cidr, d+"/128")
				} else {
					r.cidr = append(r.cidr, d+"/32")
				}
			default:
				d = strings.TrimPrefix(strings.TrimPrefix(d, "domain:"), "*.")
				d = strings.TrimPrefix(d, ".")
				if d != "" {
					r.suffix = append(r.suffix, toASCIIDomain(d))
				}
			}
		}
	}
	return r
}

func (r domainRule) rules(set M) (route []M, dns []M) {
	if len(r.suffix) > 0 || len(r.keyword) > 0 {
		m := M{}
		dm := M{}
		if len(r.suffix) > 0 {
			m["domain_suffix"] = r.suffix
			dm["domain_suffix"] = r.suffix
		}
		if len(r.keyword) > 0 {
			m["domain_keyword"] = r.keyword
			dm["domain_keyword"] = r.keyword
		}
		for k, v := range set {
			m[k] = v
		}
		route = append(route, m)
		dns = append(dns, dm)
	}
	if len(r.cidr) > 0 {
		m := M{"ip_cidr": r.cidr}
		for k, v := range set {
			m[k] = v
		}
		route = append(route, m)
	}
	return
}

func ruleSet(dir, tag string) M {
	return M{"type": "local", "tag": tag, "format": "binary", "path": filepath.Join(dir, tag+".srs")}
}

const adsTag = "adguard-dns"

var adAllowSuffix = []string{
	"forter.com", "signifyd.com", "siftscience.com", "sift.com", "riskified.com", "online-metrix.net",
	"fpjs.io", "fpnpmcdn.net", "openfpcdn.io", "perfdrive.com", "datadome.co", "captcha-delivery.com",
	"px-cdn.net", "px-cloud.net", "perimeterx.net", "arkoselabs.com", "funcaptcha.com", "geetest.com",
	"hcaptcha.com", "recaptcha.net", "iesnare.com", "cardinalcommerce.com", "kount.net", "kaptcha.com",
	"jdoqocy.com", "anrdoezrs.net", "dpbolvw.net", "kqzyfj.com", "tkqlhce.com", "awin1.com",
	"lenkmio.com", "alitems.site", "alitems.com", "gdeslon.ru", "redirectingat.com",
	"ct.sendgrid.net", "list-manage.com", "mandrillapp.com", "awstrack.me", "sparkpostmail.com", "rs6.net", "hubspotlinks.com",
	"yext.com", "ipinfodb.com", "tripod.com", "websitewelcome.com",
}

var adAllowDomain = []string{
	"hotjar.com", "www.hotjar.com", "insights.hotjar.com",
	"segment.com", "www.segment.com", "app.segment.com",
	"bizrate.com", "www.bizrate.com", "browser-update.org", "www.browser-update.org",
	"click.linksynergy.com", "ad.admitad.com", "s.click.aliexpress.com",
}

func adRule() M {
	return M{"type": "logical", "mode": "and", "rules": []M{
		{"rule_set": []string{adsTag}},
		{"domain": adAllowDomain, "domain_suffix": adAllowSuffix, "invert": true},
	}}
}

func BuildSingbox(n *Node, s *Settings, rp RunPorts, rulesDir string, viaXray bool) (M, error) {
	var outbounds []M
	var endpoints []M
	outbounds = append(outbounds, M{"type": "direct", "tag": "direct"})
	if viaXray {
		o := M{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": rp.Xray, "version": "5"}
		if rp.XUser != "" {
			o["username"], o["password"] = rp.XUser, rp.XPass
		}
		outbounds = append(outbounds, o)
	} else {
		o, ep, err := SingboxOutbound(n, "proxy")
		if err != nil {
			return nil, err
		}
		if ep {
			endpoints = append(endpoints, o)
		} else {
			outbounds = append(outbounds, o)
		}
	}

	mixed := M{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": rp.Mixed}
	if rp.User != "" {
		mixed["users"] = []M{{"username": rp.User, "password": rp.Pass}}
	}
	inbounds := []M{mixed}
	lan := s.AllowLAN && !isAndroid && s.LanUser != "" && s.LanPass != ""
	if lan {
		inbounds = append(inbounds, M{"type": "mixed", "tag": "lan-in", "listen": "0.0.0.0", "listen_port": rp.Mixed + 1,
			"users": []M{{"username": s.LanUser, "password": s.LanPass}}})
	}
	if s.Mode == "tun" && !isAndroid {
		addr := []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}
		mtu := s.MTU
		if mtu <= 0 {
			mtu = 9000
		}
		tun := M{"type": "tun", "tag": "tun-in", "interface_name": "VolframTUN", "address": addr, "mtu": mtu, "auto_route": true, "strict_route": s.StrictRoute}
		if s.TunStack != "" {
			tun["stack"] = s.TunStack
		}
		inbounds = append(inbounds, tun)
	}

	strategy := "ipv4_only"
	if s.IPv6 {
		strategy = "prefer_ipv4"
	}
	dnsServers := []M{
		dnsServer("dns-remote", s.RemoteDNS, "proxy"),
		dnsServer("dns-direct", s.DirectDNS, ""),
		localDNS("dns-local"),
	}
	var dnsRules []M
	routeRules := []M{
		{"action": "sniff"},
		{"protocol": "dns", "action": "hijack-dns"},
	}
	if isAndroid {
		routeRules = append(routeRules, M{"ip_cidr": []string{"172.19.0.2/32"}, "action": "reject"})
	}
	if lan {
		routeRules = append(routeRules,
			M{"inbound": []string{"lan-in"}, "action": "resolve"},
			M{"inbound": []string{"lan-in"}, "ip_cidr": []string{"127.0.0.0/8", "0.0.0.0/8", "::1/128", "::/128"}, "action": "reject"})
	}
	routeRules = append(routeRules, M{"ip_is_private": true, "outbound": "direct"})
	if s.Mode == "tun" && !s.IPv6 {
		routeRules = append(routeRules, M{"ip_version": 6, "action": "reject"})
	}
	if viaXray && s.Mode == "tun" && !isAndroid {
		routeRules = append(routeRules, M{"process_name": []string{"xray.exe", "xray"}, "outbound": "direct"})
	}
	addList := func(list []string, set M, dnsServerTag string, dnsAction string) {
		rr, dr := parseDomainList(list).rules(set)
		routeRules = append(routeRules, rr...)
		for _, d := range dr {
			if dnsAction != "" {
				d["action"] = dnsAction
			} else {
				d["server"] = dnsServerTag
			}
			dnsRules = append(dnsRules, d)
		}
	}
	addList(s.BlockDomains, M{"action": "reject"}, "", "reject")
	addList(s.DirectDomains, M{"outbound": "direct"}, "dns-direct", "")
	addList(s.ProxyDomains, M{"outbound": "proxy"}, "dns-remote", "")

	used := map[string]bool{}
	if s.BlockAds {
		used[adsTag] = true
		r := adRule()
		r["action"] = "reject"
		routeRules = append(routeRules, r)
		d := adRule()
		d["action"], d["rcode"] = "predefined", "NXDOMAIN"
		dnsRules = append(dnsRules, d)
	}
	final, dnsFinal := "proxy", "dns-remote"
	ruDomains := []string{"ru", "su", "xn--p1ai"}
	switch s.Routing {
	case "smart":
		used["geosite-category-ru"], used["geoip-ru"] = true, true
		routeRules = append(routeRules,
			M{"domain_suffix": ruDomains, "outbound": "direct"},
			M{"rule_set": []string{"geosite-category-ru", "geoip-ru"}, "outbound": "direct"})
		dnsRules = append(dnsRules,
			M{"domain_suffix": ruDomains, "server": "dns-direct"},
			M{"rule_set": []string{"geosite-category-ru"}, "server": "dns-direct"})
	case "blocked":
		used["geosite-ru-blocked"], used["geoip-ru-blocked"] = true, true
		routeRules = append(routeRules, M{"rule_set": []string{"geosite-ru-blocked", "geoip-ru-blocked"}, "outbound": "proxy"})
		dnsRules = append(dnsRules, M{"rule_set": []string{"geosite-ru-blocked"}, "server": "dns-remote"})
		final, dnsFinal = "direct", "dns-direct"
	}
	var ruleSets []M
	for _, tag := range []string{adsTag, "geosite-category-ru", "geoip-ru", "geosite-ru-blocked", "geoip-ru-blocked"} {
		if used[tag] {
			ruleSets = append(ruleSets, ruleSet(rulesDir, tag))
		}
	}

	level := s.LogLevel
	if level == "" {
		level = "info"
	}
	cfg := M{
		"log": M{"level": level, "timestamp": true},
		"dns": M{
			"servers":  dnsServers,
			"rules":    dnsRules,
			"final":    dnsFinal,
			"strategy": strategy,
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": M{
			"rules":                   routeRules,
			"rule_set":                ruleSets,
			"final":                   final,
			"auto_detect_interface":   !isAndroid,
			"default_domain_resolver": "dns-direct",
		},
		"experimental": M{
			"clash_api": clashAPI(rp),
		},
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	androidCerts(cfg)
	if len(dnsRules) == 0 {
		delete(cfg["dns"].(M), "rules")
	}
	if len(ruleSets) == 0 {
		delete(cfg["route"].(M), "rule_set")
	}
	return cfg, nil
}

func androidCerts(cfg M) {
	if isAndroid {
		cfg["certificate"] = M{"store": "mozilla"}
	}
}

func BuildTester(tags []string, nodes []*Node, s *Settings, rp RunPorts, ports []int) (M, map[string]string) {
	outbounds := []M{{"type": "direct", "tag": "direct"}}
	var endpoints, inbounds, rules []M
	pos := map[string]string{}
	for i, n := range nodes {
		o, ep, err := SingboxOutbound(n, tags[i])
		if err != nil {
			continue
		}
		if ep {
			pos[fmt.Sprintf("endpoint[%d]", len(endpoints))] = tags[i]
			endpoints = append(endpoints, o)
		} else {
			pos[fmt.Sprintf("outbound[%d]", len(outbounds))] = tags[i]
			outbounds = append(outbounds, o)
		}
		if i < len(ports) && ports[i] > 0 {
			in := "in-" + tags[i]
			ib := M{"type": "mixed", "tag": in, "listen": "127.0.0.1", "listen_port": ports[i]}
			if rp.User != "" {
				ib["users"] = []M{{"username": rp.User, "password": rp.Pass}}
			}
			inbounds = append(inbounds, ib)
			rules = append(rules, M{"inbound": []string{in}, "outbound": tags[i]})
		}
	}
	route := M{"final": "direct", "auto_detect_interface": !isAndroid, "default_domain_resolver": "dns-direct"}
	if len(rules) > 0 {
		route["rules"] = rules
	}
	cfg := M{
		"log":          M{"level": "error"},
		"dns":          M{"servers": []M{dnsServer("dns-direct", s.DirectDNS, ""), localDNS("dns-local")}, "strategy": "ipv4_only"},
		"outbounds":    outbounds,
		"route":        route,
		"experimental": M{"clash_api": clashAPI(rp)},
	}
	if len(inbounds) > 0 {
		cfg["inbounds"] = inbounds
	}
	androidCerts(cfg)
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	return cfg, pos
}

func xrayStream(n *Node) M {
	netw := n.Net
	switch netw {
	case "", "tcp":
		netw = "raw"
	case "mkcp":
		netw = "kcp"
	case "h2", "http":
		netw = "xhttp"
	}
	st := M{"network": netw}
	sec := n.Security
	if sec == "" {
		sec = "none"
	}
	st["security"] = sec
	fp := strings.ToLower(n.FP)
	switch sec {
	case "tls":
		t := M{}
		if sni := defaultSNI(n); sni != "" {
			t["serverName"] = sni
		}
		if fp != "" {
			t["fingerprint"] = fp
		}
		if len(n.ALPN) > 0 {
			t["alpn"] = n.ALPN
		}
		st["tlsSettings"] = t
	case "reality":
		if fp == "" {
			fp = "chrome"
		}
		r := M{"fingerprint": fp, "publicKey": n.PBK}
		if sni := defaultSNI(n); sni != "" {
			r["serverName"] = sni
		}
		if n.SID != "" {
			r["shortId"] = n.SID
		}
		if n.SPX != "" {
			r["spiderX"] = n.SPX
		}
		if n.PQV != "" {
			r["mldsa65Verify"] = n.PQV
		}
		st["realitySettings"] = r
	}
	switch netw {
	case "xhttp":
		x := M{}
		if n.Path != "" {
			x["path"] = n.Path
		}
		if n.HostHdr != "" {
			x["host"] = n.HostHdr
		}
		if n.Mode != "" {
			x["mode"] = n.Mode
		}
		if n.Extra != "" {
			var e any
			if json.Unmarshal([]byte(n.Extra), &e) == nil {
				x["extra"] = e
			}
		}
		st["xhttpSettings"] = x
	case "kcp":
		k := M{}
		if n.HeaderType != "" && n.HeaderType != "none" {
			k["header"] = M{"type": n.HeaderType}
		}
		if n.Seed != "" {
			k["seed"] = n.Seed
		}
		st["kcpSettings"] = k
	case "raw":
		if strings.EqualFold(n.HeaderType, "http") {
			req := M{}
			if n.Path != "" {
				req["path"] = splitList(n.Path)
			}
			if n.HostHdr != "" {
				req["headers"] = M{"Host": splitList(n.HostHdr)}
			}
			st["rawSettings"] = M{"header": M{"type": "http", "request": req}}
		}
	case "grpc":
		g := M{"serviceName": n.ServiceName}
		if strings.EqualFold(n.Mode, "multi") {
			g["multiMode"] = true
		}
		if n.Authority != "" {
			g["authority"] = n.Authority
		}
		st["grpcSettings"] = g
	case "ws":
		w := M{"path": n.Path}
		if n.HostHdr != "" {
			w["host"] = n.HostHdr
		}
		st["wsSettings"] = w
	case "httpupgrade":
		h := M{"path": n.Path}
		if n.HostHdr != "" {
			h["host"] = n.HostHdr
		}
		st["httpupgradeSettings"] = h
	}
	return st
}

func xrayOutbound(n *Node, tag string) (M, error) {
	var ob M
	switch n.Proto {
	case "vless":
		enc := n.Encryption
		if enc == "" {
			enc = "none"
		}
		u := M{"id": n.UUID, "encryption": enc}
		if n.Flow != "" {
			u["flow"] = n.Flow
		}
		ob = M{"protocol": "vless", "settings": M{"vnext": []M{{"address": n.Host, "port": n.Port, "users": []M{u}}}}}
	case "vmess":
		sec := n.VmessSec
		if sec == "" {
			sec = "auto"
		}
		ob = M{"protocol": "vmess", "settings": M{"vnext": []M{{"address": n.Host, "port": n.Port, "users": []M{{"id": n.UUID, "alterId": n.AlterID, "security": sec}}}}}}
	case "trojan":
		ob = M{"protocol": "trojan", "settings": M{"servers": []M{{"address": n.Host, "port": n.Port, "password": n.Password}}}}
	default:
		return nil, fmt.Errorf("протокол %s не поддерживается ядром Xray", n.Proto)
	}
	ob["tag"] = tag
	ob["streamSettings"] = xrayStream(n)
	return ob, nil
}

func xrayLogLevel(logLevel string) string {
	switch logLevel {
	case "debug", "trace":
		return "info"
	case "error":
		return "error"
	}
	return "warning"
}

func BuildXray(n *Node, port int, logLevel string) (M, error) {
	return BuildXrayAuth(n, RunPorts{Xray: port}, logLevel)
}

func BuildXrayAuth(n *Node, rp RunPorts, logLevel string) (M, error) {
	ob, err := xrayOutbound(n, "proxy")
	if err != nil {
		return nil, err
	}
	return xrayPlatform(M{
		"log":       M{"loglevel": xrayLogLevel(logLevel)},
		"inbounds":  []M{{"tag": "socks-in", "listen": "127.0.0.1", "port": rp.Xray, "protocol": "socks", "settings": xraySocks(rp.XUser, rp.XPass)}},
		"outbounds": []M{ob, {"protocol": "freedom", "tag": "direct"}},
	}), nil
}

func xrayPlatform(cfg M) M {
	if !isAndroid {
		return cfg
	}
	var servers []any
	for _, d := range sysDNS() {
		servers = append(servers, d)
	}
	cfg["dns"] = M{"servers": servers, "queryStrategy": "UseIPv4", "tag": "dns-internal"}
	rt, _ := cfg["routing"].(M)
	if rt == nil {
		rt = M{}
		cfg["routing"] = rt
	}
	rules, _ := rt["rules"].([]M)
	rt["rules"] = append([]M{{"type": "field", "inboundTag": []string{"dns-internal"}, "outboundTag": "direct"}}, rules...)
	outs, _ := cfg["outbounds"].([]M)
	for _, o := range outs {
		st, ok := o["streamSettings"].(M)
		if !ok {
			st = M{}
			o["streamSettings"] = st
		}
		so, ok := st["sockopt"].(M)
		if !ok {
			so = M{}
			st["sockopt"] = so
		}
		so["domainStrategy"] = "UseIPv4"
	}
	return cfg
}

func BuildXrayTester(nodes []*Node, ports []int, user, pass string) M {
	var ins, outs, rules []M
	for i, n := range nodes {
		ob, err := xrayOutbound(n, fmt.Sprintf("p%d", i))
		if err != nil {
			continue
		}
		in := fmt.Sprintf("in%d", i)
		ins = append(ins, M{"tag": in, "listen": "127.0.0.1", "port": ports[i], "protocol": "socks", "settings": xraySocks(user, pass)})
		outs = append(outs, ob)
		rules = append(rules, M{"type": "field", "inboundTag": []string{in}, "outboundTag": ob["tag"]})
	}
	outs = append(outs, M{"protocol": "freedom", "tag": "direct"})
	return xrayPlatform(M{
		"log":       M{"loglevel": "error"},
		"inbounds":  ins,
		"outbounds": outs,
		"routing":   M{"rules": rules},
	})
}
