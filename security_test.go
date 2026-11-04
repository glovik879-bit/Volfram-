package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHostIsLocal(t *testing.T) {
	local := []string{"localhost", "a.localhost", "127.0.0.1", "[::1]", "::1", "10.1.2.3", "192.168.0.1", "172.16.5.5", "169.254.169.254", "100.64.0.1", "0.0.0.0", "fe80::1", "::ffff:127.0.0.1"}
	public := []string{"example.com", "8.8.8.8", "1.1.1.1", "100.128.0.1", "2a00:1450::1", "", "localhost.example.com"}
	for _, h := range local {
		if !hostIsLocal(h) {
			t.Errorf("%q must be local", h)
		}
	}
	for _, h := range public {
		if hostIsLocal(h) {
			t.Errorf("%q must not be local", h)
		}
	}
}

func TestFetchBlocksLoopbackByName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	a := NewApp(t.TempDir(), t.TempDir())
	if _, body, err := a.fetch(srv.URL, 0); err != nil || string(body) != "ok" {
		t.Fatalf("direct loopback fetch must work: %v", err)
	}
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	_, _, err := a.fetch("http://localtest.me:"+port+"/", 0)
	if err == nil {
		t.Fatal("fetch by name resolving to loopback must be refused")
	}
	if !strings.Contains(err.Error(), "этот компьютер") {
		t.Skipf("localtest.me did not resolve: %v", err)
	}
}

func TestLocalRedirectAllowed(t *testing.T) {
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("secret")) }))
	defer inner.Close()
	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, inner.URL, http.StatusFound)
	}))
	defer outer.Close()
	a := NewApp(t.TempDir(), t.TempDir())
	if _, body, err := a.fetch(outer.URL, 0); err != nil || string(body) != "secret" {
		t.Fatalf("local to local redirect must work: %v", err)
	}
}
