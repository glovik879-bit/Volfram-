package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Settings struct {
	Mode           string   `json:"mode"`
	Routing        string   `json:"routing"`
	MixedPort      int      `json:"mixedPort"`
	AllowLAN       bool     `json:"allowLan"`
	BlockAds       bool     `json:"blockAds"`
	RemoteDNS      string   `json:"remoteDns"`
	DirectDNS      string   `json:"directDns"`
	IPv6           bool     `json:"ipv6"`
	TunStack       string   `json:"tunStack"`
	StrictRoute    bool     `json:"strictRoute"`
	MTU            int      `json:"mtu"`
	LogLevel       string   `json:"logLevel"`
	AutoConnect    bool     `json:"autoConnect"`
	Autostart      bool     `json:"autostart"`
	AutoUpdateSubs bool     `json:"autoUpdateSubs"`
	TestURL        string   `json:"testUrl"`
	PingMode       string   `json:"pingMode"`
	ProxyDomains   []string `json:"proxyDomains"`
	DirectDomains  []string `json:"directDomains"`
	BlockDomains   []string `json:"blockDomains"`
	Sort           string   `json:"sort"`
	AppMode        string   `json:"appMode"`
	Apps           []string `json:"apps"`
	LanUser        string   `json:"lanUser"`
	LanPass        string   `json:"lanPass"`
	CloseToTray    bool     `json:"closeToTray"`
}

func defaultSettings() Settings {
	return Settings{
		Mode: defaultMode, Routing: "smart", AppMode: "off", MixedPort: 10808, RemoteDNS: "https://1.1.1.1/dns-query",
		DirectDNS: "77.88.8.8", StrictRoute: true, MTU: 9000, LogLevel: "info", AutoUpdateSubs: true, CloseToTray: true,
		TestURL: "https://www.gstatic.com/generate_204", Sort: "default", PingMode: defaultPingMode,
	}
}

type Server struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Proto  string   `json:"proto"`
	Host   string   `json:"host"`
	Port   int      `json:"port"`
	Link   string   `json:"link"`
	SubID  string   `json:"subId"`
	Delay  int      `json:"delay"`
	Tags   []string `json:"tags"`
	Core   string   `json:"core"`
	Added  int64    `json:"added"`
	Custom bool     `json:"customName"`
}

type Subscription struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Updated  int64  `json:"updated"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
	Total    int64  `json:"total"`
	Expire   int64  `json:"expire"`
	Count    int    `json:"count"`
	Error    string `json:"error"`
	WebPage  string `json:"webPage"`
	Announce string `json:"announce"`
}

type Store struct {
	mu       sync.Mutex
	path     string
	Settings Settings        `json:"settings"`
	Servers  []*Server       `json:"servers"`
	Subs     []*Subscription `json:"subs"`
	Selected string          `json:"selected"`
	DeviceID string          `json:"deviceId,omitempty"`
}

func LoadStore(path string) *Store {
	s := &Store{path: path, Settings: defaultSettings()}
	if b, err := os.ReadFile(path); err == nil {
		plain, err := openData(b)
		if err != nil {
			_ = os.Rename(path, path+".unreadable")
		} else if err := json.Unmarshal(plain, s); err != nil {
			_ = os.Rename(path, path+".broken")
			s = &Store{path: path, Settings: defaultSettings()}
		}
	}
	for _, sv := range s.Servers {
		if n, err := ParseLink(sv.Link); err == nil {
			sv.Tags, sv.Core = n.Tags(), n.Core()
		}
	}
	d := defaultSettings()
	if s.Settings.MixedPort == 0 {
		s.Settings.MixedPort = d.MixedPort
	}
	if s.Settings.Mode == "" {
		s.Settings.Mode = d.Mode
	}
	if s.Settings.Routing == "" {
		s.Settings.Routing = d.Routing
	}
	if s.Settings.RemoteDNS == "" {
		s.Settings.RemoteDNS = d.RemoteDNS
	}
	if s.Settings.DirectDNS == "" {
		s.Settings.DirectDNS = d.DirectDNS
	}
	if s.Settings.TestURL == "" {
		s.Settings.TestURL = d.TestURL
	}
	if s.Settings.PingMode != "tcp" && s.Settings.PingMode != "get" {
		s.Settings.PingMode = d.PingMode
	}
	if s.Settings.LogLevel == "" {
		s.Settings.LogLevel = d.LogLevel
	}
	if s.Settings.MTU == 0 {
		s.Settings.MTU = d.MTU
	}
	normalizeSettings(&s.Settings)
	if s.Settings.LanUser == "" || s.Settings.LanPass == "" {
		s.Settings.LanUser, s.Settings.LanPass = "volfram-"+randHex(2), randHex(10)
	}
	for _, sv := range s.Servers {
		sv.Name = cleanText(sv.Name, 120)
	}
	if s.Servers == nil {
		s.Servers = []*Server{}
	}
	if s.Subs == nil {
		s.Subs = []*Subscription{}
	}
	return s
}

func (s *Store) Save() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	_ = os.MkdirAll(filepath.Dir(s.path), 0o700)
	_ = os.Chmod(filepath.Dir(s.path), 0o700)
	sealed, err := sealData(b)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) find(id string) *Server {
	for _, sv := range s.Servers {
		if sv.ID == id {
			return sv
		}
	}
	return nil
}

func serverFromNode(n *Node, subID string) *Server {
	return &Server{
		ID: linkID(n.Link), Name: cleanText(n.Name, 120), Proto: n.Proto, Host: n.Host, Port: n.Port, Link: n.Link,
		SubID: subID, Tags: n.Tags(), Core: n.Core(), Added: time.Now().Unix(),
	}
}

func normalizeSettings(st *Settings) {
	d := defaultSettings()
	if st.MixedPort < 1024 || st.MixedPort > 65534 {
		st.MixedPort = d.MixedPort
	}
	if !oneOf(st.Mode, "tun", "proxy") {
		st.Mode = d.Mode
	}
	if !oneOf(st.Routing, "smart", "global", "blocked") {
		st.Routing = d.Routing
	}
	if !oneOf(st.AppMode, "off", "bypass", "only") {
		st.AppMode = d.AppMode
	}
	if !oneOf(st.LogLevel, "error", "warn", "info", "debug") {
		st.LogLevel = d.LogLevel
	}
	if !oneOf(st.TunStack, "", "system", "gvisor", "mixed") {
		st.TunStack = ""
	}
	if st.MTU != 0 && (st.MTU < 1280 || st.MTU > 65535) {
		st.MTU = d.MTU
	}
	if !validDNSSpec(st.RemoteDNS) {
		st.RemoteDNS = d.RemoteDNS
	}
	if !validDNSSpec(st.DirectDNS) {
		st.DirectDNS = d.DirectDNS
	}
	if u, ok := webURL(st.TestURL); ok {
		st.TestURL = u
	} else {
		st.TestURL = d.TestURL
	}
}
