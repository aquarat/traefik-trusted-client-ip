package traefik_trusted_client_ip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type seen struct {
	remoteAddr string
	xff        string
	xRealIP    string
	forwarded  string
	source     string
	called     bool
}

func build(t *testing.T, cfg *Config) (http.Handler, *seen) {
	t.Helper()
	s := &seen{}
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s.called = true
		s.remoteAddr = r.RemoteAddr
		s.xff = r.Header.Get("X-Forwarded-For")
		s.xRealIP = r.Header.Get("X-Real-Ip")
		s.forwarded = r.Header.Get("Forwarded")
		s.source = r.Header.Get("CF-Connecting-IP")
	})
	h, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h, s
}

func cfg(trusted ...string) *Config {
	c := CreateConfig()
	c.TrustedCIDRs = trusted
	return c
}

func req(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestTrustedPeerReplacesSpoofedXFF(t *testing.T) {
	h, s := build(t, cfg("172.19.0.1/32"))
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req("172.19.0.1:40000", map[string]string{
		"X-Forwarded-For":  "203.0.113.77, 198.51.100.9",
		"X-Real-Ip":        "203.0.113.77",
		"Forwarded":        "for=203.0.113.77",
		"CF-Connecting-IP": "198.51.100.9",
	}))
	if !s.called {
		t.Fatal("next not called")
	}
	if s.xff != "198.51.100.9" || s.xRealIP != "198.51.100.9" {
		t.Fatalf("xff=%q xrealip=%q", s.xff, s.xRealIP)
	}
	if s.forwarded != "" {
		t.Fatalf("Forwarded not removed: %q", s.forwarded)
	}
	if s.remoteAddr != "198.51.100.9:40000" {
		t.Fatalf("remoteAddr=%q", s.remoteAddr)
	}
	if s.source != "198.51.100.9" {
		t.Fatalf("source header should be kept for trusted peers, got %q", s.source)
	}
}

func TestTrustedPeerIPv6Client(t *testing.T) {
	h, s := build(t, cfg("172.19.0.1"))
	h.ServeHTTP(httptest.NewRecorder(), req("172.19.0.1:1234", map[string]string{
		"CF-Connecting-IP": "2001:db8::1",
	}))
	if s.xff != "2001:db8::1" || s.remoteAddr != "[2001:db8::1]:1234" {
		t.Fatalf("xff=%q remote=%q", s.xff, s.remoteAddr)
	}
}

func TestIPv4MappedIsNormalised(t *testing.T) {
	h, s := build(t, cfg("172.19.0.1"))
	h.ServeHTTP(httptest.NewRecorder(), req("172.19.0.1:1", map[string]string{
		"CF-Connecting-IP": "::ffff:198.51.100.9",
	}))
	if s.xff != "198.51.100.9" {
		t.Fatalf("xff=%q", s.xff)
	}
}

func TestUntrustedPeerIsStripped(t *testing.T) {
	h, s := build(t, cfg("172.19.0.1/32"))
	h.ServeHTTP(httptest.NewRecorder(), req("192.168.0.50:5555", map[string]string{
		"X-Forwarded-For":  "203.0.113.77",
		"X-Real-Ip":        "203.0.113.77",
		"Forwarded":        "for=203.0.113.77",
		"CF-Connecting-IP": "203.0.113.77",
	}))
	if s.xff != "" || s.xRealIP != "" || s.forwarded != "" || s.source != "" {
		t.Fatalf("headers kept: %+v", s)
	}
	if s.remoteAddr != "192.168.0.50:5555" {
		t.Fatalf("remoteAddr changed: %q", s.remoteAddr)
	}
}

func TestUntrustedPeerKeptWhenStripDisabled(t *testing.T) {
	c := cfg("172.19.0.1/32")
	f := false
	c.StripUntrusted = &f
	h, s := build(t, c)
	h.ServeHTTP(httptest.NewRecorder(), req("192.168.0.50:5555", map[string]string{
		"CF-Connecting-IP": "203.0.113.77",
	}))
	if s.source != "203.0.113.77" {
		t.Fatalf("source=%q", s.source)
	}
}

func TestNoTrustedPeersOnlyStrips(t *testing.T) {
	h, s := build(t, cfg())
	h.ServeHTTP(httptest.NewRecorder(), req("172.19.0.1:1", map[string]string{
		"CF-Connecting-IP": "198.51.100.9",
		"X-Forwarded-For":  "203.0.113.77",
	}))
	if s.xff != "" || s.source != "" {
		t.Fatalf("headers kept: %+v", s)
	}
}

func TestMissingOrInvalidHeaderStrips(t *testing.T) {
	for _, v := range []string{"", "not-an-ip", "198.51.100.9, 203.0.113.77", "198.51.100.9:80", "fe80::1%eth0", " "} {
		h, s := build(t, cfg("172.19.0.1"))
		hdr := map[string]string{"X-Forwarded-For": "203.0.113.77", "X-Real-Ip": "203.0.113.77"}
		if v != "" {
			hdr["CF-Connecting-IP"] = v
		}
		h.ServeHTTP(httptest.NewRecorder(), req("172.19.0.1:9", hdr))
		if !s.called {
			t.Fatalf("%q: next not called", v)
		}
		if s.xff != "" || s.xRealIP != "" {
			t.Fatalf("%q: spoofed headers kept: xff=%q xrealip=%q", v, s.xff, s.xRealIP)
		}
		if s.remoteAddr != "172.19.0.1:9" {
			t.Fatalf("%q: remoteAddr changed to %q", v, s.remoteAddr)
		}
	}
}

func TestMissingHeaderReject(t *testing.T) {
	c := cfg("172.19.0.1")
	c.OnMissing = "reject"
	h, s := build(t, c)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req("172.19.0.1:9", nil))
	if s.called || rw.Code != http.StatusBadRequest {
		t.Fatalf("called=%v code=%d", s.called, rw.Code)
	}
}

func TestRewriteRemoteAddrDisabled(t *testing.T) {
	c := cfg("172.19.0.1")
	f := false
	c.RewriteRemoteAddr = &f
	h, s := build(t, c)
	h.ServeHTTP(httptest.NewRecorder(), req("172.19.0.1:9", map[string]string{"CF-Connecting-IP": "198.51.100.9"}))
	if s.remoteAddr != "172.19.0.1:9" || s.xff != "198.51.100.9" {
		t.Fatalf("remote=%q xff=%q", s.remoteAddr, s.xff)
	}
}

func TestCustomSourceHeader(t *testing.T) {
	c := cfg("10.0.0.0/8")
	c.SourceHeader = "True-Client-IP"
	h, s := build(t, c)
	h.ServeHTTP(httptest.NewRecorder(), req("10.1.2.3:9", map[string]string{"True-Client-IP": "198.51.100.9"}))
	if s.xff != "198.51.100.9" {
		t.Fatalf("xff=%q", s.xff)
	}
}

func TestInvalidConfig(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, c := range []*Config{
		{TrustedCIDRs: []string{"nonsense"}},
		{TrustedCIDRs: []string{"10.0.0.0/99"}},
		{OnMissing: "explode"},
	} {
		if _, err := New(context.Background(), next, c, "test"); err == nil {
			t.Fatalf("expected error for %+v", c)
		}
	}
}

func TestIPv6TrustedPeer(t *testing.T) {
	h, s := build(t, cfg("fd00::/8"))
	h.ServeHTTP(httptest.NewRecorder(), req("[fd00::5]:443", map[string]string{"CF-Connecting-IP": "198.51.100.9"}))
	if s.xff != "198.51.100.9" {
		t.Fatalf("xff=%q", s.xff)
	}
}

func TestSecondInstanceIsNoop(t *testing.T) {
	inner, s := build(t, cfg("172.19.0.1"))
	outer, err := New(context.Background(), inner, cfg("172.19.0.1"), "outer")
	if err != nil {
		t.Fatal(err)
	}
	outer.ServeHTTP(httptest.NewRecorder(), req("172.19.0.1:9", map[string]string{
		"CF-Connecting-IP": "198.51.100.9",
		"X-Forwarded-For":  "203.0.113.77",
	}))
	if s.xff != "198.51.100.9" || s.source != "198.51.100.9" || s.remoteAddr != "198.51.100.9:9" {
		t.Fatalf("second instance changed the request: %+v", s)
	}
}
