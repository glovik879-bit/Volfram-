package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var testLinks = []string{
	"vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba85179e30d4fc2&spx=%2F&type=tcp#%F0%9F%87%A9%F0%9F%87%AA%20Germany%20Reality",
	"vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?encryption=none&security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fws%3Fed%3D2048#WS%20TLS",
	"vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?encryption=none&security=reality&sni=yahoo.com&fp=chrome&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=ab&type=grpc&serviceName=grpc#gRPC",
	"vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?encryption=none&security=reality&sni=yahoo.com&fp=chrome&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=ab&type=xhttp&path=%2Fxh&mode=auto#%F0%9F%87%B3%F0%9F%87%B1%20XHTTP",
	"vmess://" + "eyJ2IjoiMiIsInBzIjoiVk1lc3MgV1MiLCJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiJleGFtcGxlLmNvbSIsInBhdGgiOiIvdm1lc3MiLCJ0bHMiOiJ0bHMiLCJzbmkiOiJleGFtcGxlLmNvbSJ9",
	"trojan://pass%40word@example.com:443?security=tls&sni=example.com&type=tcp#Trojan",
	"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@1.2.3.4:8388#SS%20classic",
	"ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@1.2.3.4:8388#SS2022",
	"ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40OjQ0Mw==#SS%20legacy",
	"hysteria2://secret@hy.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=obfspw&insecure=1#Hy2",
	"hy2://secret@hy.example.com:443,20000-30000/?sni=hy.example.com#Hy2%20hop",
	"tuic://11111111-2222-3333-4444-555555555555:pw@tuic.example.com:443?congestion_control=bbr&alpn=h3&sni=tuic.example.com&udp_relay_mode=native#TUIC",
	"hysteria://hy1.example.com:443?protocol=udp&auth=abc&peer=hy1.example.com&upmbps=50&downmbps=100&alpn=hysteria#Hy1",
	"wireguard://cGhNb3JIYWNrZXJMb2xLZXlGb3JXR1Rlc3QxMjM0NTY3OD0=@wg.example.com:51820?publickey=bmVzdFB1YmxpY0tleUZvcldpcmVHdWFyZFRlc3RzMTIzND0%3D&address=10.0.0.2%2F32&mtu=1280&reserved=1,2,3#WG",
	"socks://dXNlcjpwYXNz@1.2.3.4:1080#SOCKS",
	"anytls://pw@any.example.com:443?sni=any.example.com#AnyTLS",
	"naive+https://user:pass@naive.example.com:443#Naive",
	"vmess://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=kcp&headerType=wechat-video&seed=abc&security=none#VMess%20KCP",
	"trojan://pw@1.2.3.4:443?security=tls&sni=a.com&type=xhttp&path=/x&mode=packet-up#Trojan%20XHTTP",
}

func TestConfigs(t *testing.T) {
	sb := os.Getenv("SB")
	xr := os.Getenv("XR")
	if sb == "" || xr == "" {
		t.Skip("SB and XR are not set")
	}
	dir := t.TempDir()
	rules := os.Getenv("RULES")
	for _, mode := range []string{"proxy", "tun"} {
		for _, routing := range []string{"global", "smart", "blocked"} {
			for i, l := range testLinks {
				n, err := ParseLink(l)
				if err != nil {
					t.Fatalf("parse %d: %v", i, err)
				}
				s := defaultSettings()
				s.Mode, s.Routing, s.BlockAds, s.IPv6 = mode, routing, true, i%2 == 0
				s.AllowLAN, s.LanUser, s.LanPass = i%3 == 0, "u", "p"
				s.ProxyDomains = []string{"youtube.com\nkeyword:google", "8.8.8.8"}
				s.DirectDomains = []string{"vk.com"}
				s.BlockDomains = []string{"ads.example.com"}
				s.RemoteDNS = []string{"https://1.1.1.1/dns-query", "tls://dns.google", "8.8.8.8"}[i%3]
				viaX := n.NeedsXray()
				cfg, err := BuildSingbox(n, &s, RunPorts{Mixed: 10808, Clash: 19090, Xray: 19091, Secret: "x"}, rules, viaX)
				if err != nil {
					t.Fatalf("build %d: %v", i, err)
				}
				b, _ := json.MarshalIndent(cfg, "", " ")
				p := filepath.Join(dir, "sb.json")
				os.WriteFile(p, b, 0o644)
				if out, err := exec.Command(sb, "check", "-c", p).CombinedOutput(); err != nil {
					t.Errorf("sing-box check %s/%s link %d (%s): %v\n%s", mode, routing, i, n.Name, err, out)
				}
				if viaX && mode == "proxy" && routing == "global" && n.XrayRefusal() != "" {
					t.Logf("xray refuses link %d (%s)", i, n.Name)
				} else if viaX && mode == "proxy" && routing == "global" {
					xc, err := BuildXray(n, 19091, "info")
					if err != nil {
						t.Fatalf("xray build %d: %v", i, err)
					}
					b, _ := json.MarshalIndent(xc, "", " ")
					xp := filepath.Join(dir, "xr.json")
					os.WriteFile(xp, b, 0o644)
					if out, err := exec.Command(xr, "run", "-test", "-c", xp).CombinedOutput(); err != nil {
						t.Errorf("xray test link %d (%s): %v\n%s\n%s", i, n.Name, err, out, b)
					}
				}
				if mode == "proxy" && routing == "global" {
					t.Logf("%-2d %-10s %-22s core=%s tags=%v", i, n.Proto, n.Name, n.Core(), n.Tags())
				}
			}
		}
	}
	var nodes []*Node
	var tags []string
	for i, l := range testLinks {
		n, _ := ParseLink(l)
		if !n.NeedsXray() {
			nodes = append(nodes, n)
			tags = append(tags, "t"+string(rune('a'+i)))
		}
	}
	s := defaultSettings()
	ports := make([]int, len(nodes))
	for i := range ports {
		ports[i] = 20100 + i
	}
	tc, _ := BuildTester(tags, nodes, &s, RunPorts{Clash: 19092, Secret: "x"}, ports)
	b, _ := json.MarshalIndent(tc, "", " ")
	p := filepath.Join(dir, "t.json")
	os.WriteFile(p, b, 0o644)
	if out, err := exec.Command(sb, "check", "-c", p).CombinedOutput(); err != nil {
		t.Errorf("tester check: %v\n%s", err, out)
	}
}
