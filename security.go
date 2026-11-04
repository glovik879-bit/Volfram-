package main

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var apiReadOnly = map[string]bool{
	"/api/state": true, "/api/events": true, "/api/logs": true, "/api/connections": true,
	"/api/apps": true, "/api/appicon": true, "/api/servers/config": true,
}

const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; " +
	"font-src 'self' data:; connect-src 'self'; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func secHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), clipboard-read=()")
	h.Set("Cache-Control", "no-store")
}

func secretEq(a, b string) bool {
	return a != "" && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func loopbackHost(r *http.Request) bool {
	h := r.Host
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func (a *App) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secHeaders(w)
		if !loopbackHost(r) {
			http.NotFound(w, r)
			return
		}
		get := r.Method == http.MethodGet || r.Method == http.MethodHead
		queryOK := secretEq(r.URL.Query().Get("t"), a.token)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			headerOK := secretEq(r.Header.Get("X-Token"), a.token)
			switch {
			case get && !apiReadOnly[r.URL.Path]:
				if headerOK || queryOK {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				http.NotFound(w, r)
				return
			case get:
				if !headerOK && !queryOK {
					http.NotFound(w, r)
					return
				}
			default:
				if r.Method != http.MethodPost && r.Method != http.MethodDelete {
					http.NotFound(w, r)
					return
				}
				if !headerOK {
					http.NotFound(w, r)
					return
				}
				if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, r)
			return
		}
		if !get {
			http.NotFound(w, r)
			return
		}
		cookieOK := false
		if c, err := r.Cookie("volfram_s"); err == nil {
			cookieOK = secretEq(c.Value, a.assetKey)
		}
		if queryOK && !cookieOK {
			http.SetCookie(w, &http.Cookie{Name: "volfram_s", Value: a.assetKey, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		} else if !cookieOK {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func cleanText(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			r = ' '
		case unicode.IsControl(r):
			continue
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E, r == 0x200F, r == 0x061C, r == 0xFEFF:
			continue
		}
		if n >= max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

func webURL(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 4096 || strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", false
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Opaque != "" {
		return "", false
	}
	return u.String(), true
}

func oneOf(v string, list ...string) bool {
	for _, x := range list {
		if v == x {
			return true
		}
	}
	return false
}

func validDNSSpec(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) <= 256 && strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || r == '"' || r == '\\' }) < 0
}

func validateSettings(s *Settings) error {
	switch {
	case s.MixedPort < 1024 || s.MixedPort > 65534:
		return errors.New("порт должен быть от 1024 до 65534")
	case !oneOf(s.Mode, "tun", "proxy"):
		return errors.New("неизвестный режим подключения")
	case !oneOf(s.Routing, "smart", "global", "blocked"):
		return errors.New("неизвестный режим маршрутизации")
	case !oneOf(s.AppMode, "off", "bypass", "only"):
		return errors.New("неизвестный режим приложений")
	case !oneOf(s.LogLevel, "error", "warn", "info", "debug"):
		return errors.New("неизвестный уровень журнала")
	case !oneOf(s.TunStack, "", "system", "gvisor", "mixed"):
		return errors.New("неизвестный сетевой стек")
	case s.MTU != 0 && (s.MTU < 1280 || s.MTU > 65535):
		return errors.New("MTU должен быть от 1280 до 65535")
	case !validDNSSpec(s.RemoteDNS) || !validDNSSpec(s.DirectDNS):
		return errors.New("некорректный адрес DNS")
	}
	if u, ok := webURL(s.TestURL); ok {
		s.TestURL = u
	} else {
		return errors.New("адрес для теста задержки должен начинаться с http:// или https://")
	}
	total := 0
	for _, l := range [][]string{s.ProxyDomains, s.DirectDomains, s.BlockDomains, s.Apps} {
		for _, v := range l {
			total += len(v)
		}
	}
	if total > 1<<20 {
		return errors.New("слишком длинные списки правил")
	}
	return nil
}

var (
	reShareLink = regexp.MustCompile(`(?i)\b(vless|vmess|trojan|ssr?|hy2|hysteria2?|tuic|anytls|socks5?h?|naive\+https?|wireguard|wg|volfram|happ)://[^\s"'<>]+`)
	reWebURL    = regexp.MustCompile(`(?i)\b(https?|wss?)://([^\s/"'?#@<>]+@)?([^\s/"'?#<>]+)([/?#][^\s"'<>]*)?`)
	reUUID      = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	reSecretKV  = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|uuid|psk|private[_-]?key|pre[_-]?shared[_-]?key)(["']?\s*[:=]\s*["']?)([^\s"',&}]+)`)
)

func redact(s string) string {
	if strings.Contains(s, "://") {
		s = reShareLink.ReplaceAllStringFunc(s, func(m string) string { return m[:strings.Index(m, "://")] + "://…" })
		s = reWebURL.ReplaceAllStringFunc(s, func(m string) string {
			p := reWebURL.FindStringSubmatch(m)
			if p[2] == "" && (p[4] == "" || p[4] == "/") {
				return m
			}
			return p[1] + "://" + p[3] + "/…"
		})
	}
	if strings.Count(s, "-") >= 4 {
		s = reUUID.ReplaceAllStringFunc(s, func(m string) string { return m[:4] + "…" })
	}
	l := strings.ToLower(s)
	if strings.Contains(l, "pass") || strings.Contains(l, "secret") || strings.Contains(l, "token") ||
		strings.Contains(l, "uuid") || strings.Contains(l, "psk") || strings.Contains(l, "key") {
		s = reSecretKV.ReplaceAllString(s, "$1$2…")
	}
	return s
}
