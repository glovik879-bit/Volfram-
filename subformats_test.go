package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestShareLinkRoundtrip(t *testing.T) {
	for i, l := range testLinks {
		n, err := ParseLink(l)
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		l2 := n.ShareLink()
		n2, err := ParseLink(l2)
		if err != nil {
			t.Fatalf("%d reparse %q: %v", i, l2, err)
		}
		a, b := *n, *n2
		a.Link, b.Link = "", ""
		for _, x := range []*Node{&a, &b} {
			if x.Security == "none" {
				x.Security = ""
			}
			if x.Net == "kcp" && x.Path == x.Seed {
				x.Path = ""
			}
		}
		if !reflect.DeepEqual(a, b) {
			ja, _ := json.Marshal(a)
			jb, _ := json.Marshal(b)
			t.Errorf("%d mismatch\n orig %s\n back %s\n link %s", i, ja, jb, l2)
		}
	}
}

const sampleXrayJSON = `[
 {"remarks":"🇳🇱 Нидерланды","dns":{"servers":["https://1.1.1.1/dns-query"]},
  "outbounds":[
   {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"nl.example.com","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none","flow":"xtls-rprx-vision"}]}]},
    "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.microsoft.com","fingerprint":"chrome","publicKey":"Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw","shortId":"6ba85179e30d4fc2","spiderX":"/"}},"mux":{"enabled":false}},
   {"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],
  "routing":{"rules":[]}},
 {"remarks":"🇩🇪 Германия XHTTP","outbounds":[
   {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"de.example.com","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none"}]}]},
    "streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"serverName":"yahoo.com","fingerprint":"chrome","publicKey":"Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw","shortId":"ab"},
     "xhttpSettings":{"path":"/xh","mode":"auto","extra":{"xPaddingBytes":"100-1000","noGRPCHeader":false}}}},
   {"tag":"direct","protocol":"freedom"}]},
 {"remarks":"🇫🇮 Финляндия WS","outbounds":[
   {"tag":"proxy","protocol":"vless","settings":{"address":"fi.example.com","port":8443,"id":"11111111-2222-3333-4444-555555555555","encryption":"none"},
    "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"fi.example.com","fingerprint":"chrome","alpn":["http/1.1"]},"wsSettings":{"path":"/ws?ed=2048","headers":{"Host":"fi.example.com"}}}}]},
 {"remarks":"🇺🇸 США Trojan gRPC","outbounds":[
   {"tag":"proxy","protocol":"trojan","settings":{"servers":[{"address":"us.example.com","port":443,"password":"pw@1"}]},
    "streamSettings":{"network":"grpc","security":"tls","tlsSettings":{"serverName":"us.example.com","allowInsecure":true},"grpcSettings":{"serviceName":"tg","multiMode":true}}}]},
 {"remarks":"🇯🇵 Япония SS","outbounds":[
   {"tag":"proxy","protocol":"shadowsocks","settings":{"servers":[{"address":"jp.example.com","port":8388,"method":"2022-blake3-aes-256-gcm","password":"YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI="}]}}]},
 {"remarks":"🇬🇧 VMess HTTPUpgrade","outbounds":[
   {"tag":"proxy","protocol":"vmess","settings":{"vnext":[{"address":"uk.example.com","port":80,"users":[{"id":"11111111-2222-3333-4444-555555555555","alterId":0,"security":"auto"}]}]},
    "streamSettings":{"network":"httpupgrade","httpupgradeSettings":{"path":"/hu","host":"uk.example.com"}}}]},
 {"remarks":"🇹🇷 mKCP","outbounds":[
   {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"tr.example.com","port":5000,"users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none"}]}]},
    "streamSettings":{"network":"kcp","kcpSettings":{"header":{"type":"wechat-video"},"seed":"s33d"}}}]},
 {"remarks":"Chained fragment","outbounds":[
   {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"fr.example.com","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none"}]}]},
    "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"fr.example.com"},"sockopt":{"dialerProxy":"fragment"}}},
   {"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"10-20"}}}]}
]`

const sampleSingbox = `{"outbounds":[
 {"type":"selector","tag":"select","outbounds":["a","b"]},
 {"type":"vless","tag":"🇳🇱 SB Reality","server":"nl.example.com","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","flow":"xtls-rprx-vision",
  "tls":{"enabled":true,"server_name":"www.microsoft.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw","short_id":"ab"}}},
 {"type":"hysteria2","tag":"SB Hy2","server":"hy.example.com","server_port":443,"server_ports":["20000:30000"],"password":"pw","obfs":{"type":"salamander","password":"o"},"tls":{"enabled":true,"server_name":"hy.example.com"}},
 {"type":"tuic","tag":"SB TUIC","server":"tuic.example.com","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","password":"pw","congestion_control":"bbr","tls":{"enabled":true,"server_name":"tuic.example.com","alpn":["h3"]}},
 {"type":"vmess","tag":"SB VMess WS","server":"vm.example.com","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","security":"auto","tls":{"enabled":true,"server_name":"vm.example.com"},"transport":{"type":"ws","path":"/v","headers":{"Host":"vm.example.com"},"max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}},
 {"type":"shadowsocks","tag":"SB SS","server":"1.2.3.4","server_port":8388,"method":"chacha20-ietf-poly1305","password":"p"},
 {"type":"anytls","tag":"SB AnyTLS","server":"any.example.com","server_port":443,"password":"pw","tls":{"enabled":true,"server_name":"any.example.com"}},
 {"type":"direct","tag":"direct"}],
 "endpoints":[{"type":"wireguard","tag":"SB WG","address":["172.16.0.2/32"],"private_key":"cGhNb3JIYWNrZXJMb2xLZXlGb3JXR1Rlc3QxMjM0NTY3OD0=","peers":[{"address":"wg.example.com","port":2408,"public_key":"bmVzdFB1YmxpY0tleUZvcldpcmVHdWFyZFRlc3RzMTIzND0=","reserved":[1,2,3]}]}]}`

const sampleClash = `mixed-port: 7890
proxies:
  - name: "🇳🇱 Clash Reality"
    type: vless
    server: nl.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: www.microsoft.com
    client-fingerprint: chrome
    reality-opts:
      public-key: Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw
      short-id: ab
  - {name: Clash VMess gRPC, type: vmess, server: vm.example.com, port: 443, uuid: 11111111-2222-3333-4444-555555555555, alterId: 0, cipher: auto, tls: true, servername: vm.example.com, network: grpc, grpc-opts: {grpc-service-name: gs}}
  - {name: Clash Trojan WS, type: trojan, server: tj.example.com, port: 443, password: pw, sni: tj.example.com, network: ws, ws-opts: {path: /tj, headers: {Host: tj.example.com}}}
  - {name: Clash SS obfs, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: p, plugin: obfs, plugin-opts: {mode: http, host: bing.com}}
  - {name: Clash Hy2, type: hysteria2, server: hy.example.com, port: 443, ports: 20000-30000, password: pw, up: "50 Mbps", down: "200 Mbps", sni: hy.example.com, skip-cert-verify: true}
  - {name: Clash TUIC, type: tuic, server: tuic.example.com, port: 443, uuid: 11111111-2222-3333-4444-555555555555, password: pw, congestion-controller: bbr, alpn: [h3], sni: tuic.example.com}
  - {name: Clash WG, type: wireguard, server: wg.example.com, port: 2408, ip: 172.16.0.2, private-key: cGhNb3JIYWNrZXJMb2xLZXlGb3JXR1Rlc3QxMjM0NTY3OD0=, public-key: bmVzdFB1YmxpY0tleUZvcldpcmVHdWFyZFRlc3RzMTIzND0=, mtu: 1280, reserved: [1, 2, 3]}
  - {name: Clash SOCKS, type: socks5, server: 1.2.3.4, port: 1080, username: u, password: p}
proxy-groups:
  - {name: PROXY, type: select, proxies: [Clash TUIC]}
`

func validateNodes(t *testing.T, nodes []*Node) {
	sb, xr := os.Getenv("SB"), os.Getenv("XR")
	if sb == "" {
		return
	}
	dir := t.TempDir()
	for i, n := range nodes {
		s := defaultSettings()
		viaX := n.NeedsXray()
		cfg, err := BuildSingbox(n, &s, RunPorts{Mixed: 10808, Clash: 19090, Xray: 19091, Secret: "x"}, os.Getenv("RULES"), viaX)
		if err != nil {
			t.Fatalf("build %d: %v", i, err)
		}
		b, _ := json.Marshal(cfg)
		p := filepath.Join(dir, "sb.json")
		os.WriteFile(p, b, 0o644)
		if out, err := exec.Command(sb, "check", "-c", p).CombinedOutput(); err != nil {
			t.Errorf("sing-box check %d (%s): %v\n%s", i, n.Name, err, out)
		}
		if viaX && n.XrayRefusal() != "" {
			t.Logf("xray refuses %d (%s): %s", i, n.Name, n.XrayRefusal())
		} else if viaX {
			xc, _ := BuildXray(n, 19091, "info")
			b, _ := json.Marshal(xc)
			xp := filepath.Join(dir, "xr.json")
			os.WriteFile(xp, b, 0o644)
			if out, err := exec.Command(xr, "run", "-test", "-c", xp).CombinedOutput(); err != nil {
				t.Errorf("xray test %d (%s): %v\n%s", i, n.Name, err, out)
			}
		}
	}
}

func TestSubFormats(t *testing.T) {
	cases := []struct {
		name, body, format string
		count              int
	}{
		{"xray", sampleXrayJSON, fmtXray, 8},
		{"xray-b64", base64.StdEncoding.EncodeToString([]byte(sampleXrayJSON)), fmtXray, 8},
		{"singbox", sampleSingbox, fmtSingbox, 7},
		{"clash", sampleClash, fmtClash, 8},
		{"html", "<!DOCTYPE html><html><head><title>x</title></head></html>", fmtHTML, 0},
		{"happ", "happ://crypt3/AAAABBBBCCCC\nhapp://crypt3/DDDD", fmtHapp, 0},
		{"links", base64.StdEncoding.EncodeToString([]byte(testLinks[0] + "\n" + testLinks[5])), fmtLinks, 2},
	}
	for _, c := range cases {
		nodes, f := ParseSubscriptionBody([]byte(c.body))
		if f != c.format || len(nodes) != c.count {
			t.Errorf("%s: format %q count %d, want %q %d", c.name, f, len(nodes), c.format, c.count)
		}
		for _, n := range nodes {
			t.Logf("%s: %-9s %-24s core=%-8s tags=%v", c.name, n.Proto, n.Name, n.Core(), n.Tags())
		}
		validateNodes(t, nodes)
	}
	nodes, _ := ParseSubscriptionBody([]byte(sampleXrayJSON))
	if n := nodes[0]; n.Security != "reality" || n.Flow != "xtls-rprx-vision" || n.PBK == "" || n.SID != "6ba85179e30d4fc2" || n.Name != "🇳🇱 Нидерланды" {
		t.Errorf("reality node wrong: %+v", n)
	}
	if n := nodes[1]; n.Net != "xhttp" || n.Extra == "" || n.Mode != "auto" || !n.NeedsXray() {
		t.Errorf("xhttp node wrong: %+v", n)
	}
	if n := nodes[2]; n.Net != "ws" || n.HostHdr != "fi.example.com" || n.Path != "/ws?ed=2048" || n.Port != 8443 {
		t.Errorf("ws node wrong: %+v", n)
	}
	if n := nodes[3]; n.Password != "pw@1" || n.Mode != "multi" || !n.Insecure {
		t.Errorf("trojan node wrong: %+v", n)
	}
	sbn, _ := ParseSubscriptionBody([]byte(sampleSingbox))
	if n := sbn[1]; n.Ports != "20000-30000" || n.Obfs != "salamander" {
		t.Errorf("hy2 node wrong: %+v", n)
	}
	cl, _ := ParseSubscriptionBody([]byte(sampleClash))
	if n := cl[4]; n.UpMbps != 50 || n.DownMbps != 200 || n.Ports != "20000-30000" {
		t.Errorf("clash hy2 wrong: %+v", n)
	}
}
