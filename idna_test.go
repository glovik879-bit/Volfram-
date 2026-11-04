package main

import "testing"

func TestIDNA(t *testing.T) {
	cases := map[string]string{
		"пример.рф":                  "xn--e1afmkfd.xn--p1ai",
		"https://пример.рф/":         "xn--e1afmkfd.xn--p1ai",
		"https://www.2ip.io/ru/?x=1": "2ip.io",
		"2ip.io:443":                 "2ip.io",
		"*.Пример.испытание":         "xn--e1afmkfd.xn--80akhbyknj4f",
		"münchen.de":                 "xn--mnchen-3ya.de",
		"xn--e1afmkfd.xn--p1ai":      "xn--e1afmkfd.xn--p1ai",
	}
	for in, want := range cases {
		r := parseDomainList([]string{in})
		if len(r.suffix) != 1 || r.suffix[0] != want {
			t.Errorf("%q -> %v, want %s", in, r.suffix, want)
		}
	}
	r := parseDomainList([]string{"10.0.0.0/8\n1.2.3.4\nkeyword:openai"})
	if len(r.cidr) != 2 || len(r.keyword) != 1 || len(r.suffix) != 0 {
		t.Errorf("mixed list: %+v", r)
	}
}
