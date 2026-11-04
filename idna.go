package main

import (
	"net"
	"net/url"
	"strings"
)

func punycodeLabel(label string) string {
	const (
		base, tmin, tmax, skew, damp = 36, 1, 26, 38, 700
		initialBias, initialN        = 72, 128
	)
	runes := []rune(label)
	var out []byte
	for _, r := range runes {
		if r < 0x80 {
			out = append(out, byte(r))
		}
	}
	b := len(out)
	if b == len(runes) {
		return label
	}
	if b > 0 {
		out = append(out, '-')
	}
	adapt := func(delta, num int, first bool) int {
		if first {
			delta /= damp
		} else {
			delta /= 2
		}
		delta += delta / num
		k := 0
		for delta > ((base-tmin)*tmax)/2 {
			delta /= base - tmin
			k += base
		}
		return k + (base-tmin+1)*delta/(delta+skew)
	}
	digit := func(d int) byte {
		if d < 26 {
			return byte('a' + d)
		}
		return byte('0' + d - 26)
	}
	n, delta, bias, h := initialN, 0, initialBias, b
	for h < len(runes) {
		m := int(^uint(0) >> 1)
		for _, r := range runes {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range runes {
			if int(r) < n {
				delta++
			}
			if int(r) == n {
				q := delta
				for k := base; ; k += base {
					t := k - bias
					if t < tmin {
						t = tmin
					} else if t > tmax {
						t = tmax
					}
					if q < t {
						break
					}
					out = append(out, digit(t+(q-t)%(base-t)))
					q = (q - t) / (base - t)
				}
				out = append(out, digit(q))
				bias = adapt(delta, h+1, h == b)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	return "xn--" + string(out)
}

func toASCIIDomain(d string) string {
	labels := strings.Split(strings.ToLower(d), ".")
	for i, l := range labels {
		labels[i] = punycodeLabel(l)
	}
	return strings.Join(labels, ".")
}

func cleanRuleEntry(d string) string {
	if strings.Contains(d, "://") {
		if u, err := url.Parse(d); err == nil && u.Host != "" {
			d = u.Host
		}
	}
	if strings.ContainsAny(d, "/?#") && !strings.Contains(d, ":") {
		if i := strings.IndexAny(d, "/?#"); i > 0 && net.ParseIP(d[:i]) == nil {
			d = d[:i]
		}
	}
	if h, _, err := net.SplitHostPort(d); err == nil && !strings.Contains(h, "/") {
		d = h
	}
	d = strings.TrimPrefix(d, "www.")
	return strings.TrimSuffix(d, ".")
}
