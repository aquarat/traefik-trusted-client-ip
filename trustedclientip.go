// Package traefik_trusted_client_ip is a Traefik middleware plugin that sets the client IP
// from a header written by a trusted upstream (by default Cloudflare's
// CF-Connecting-IP), and only when the request really comes from that upstream.
//
// Why: CDNs such as Cloudflare append the visitor's address to whatever
// X-Forwarded-For the visitor sent. Traefik can only trust or distrust a peer's
// X-Forwarded-For as a whole, so a backend that reads the leftmost entry ends up
// believing a value the visitor chose. This plugin replaces the forwarding
// headers with the single address from the trusted header instead.
package traefik_trusted_client_ip //nolint:revive,stylecheck // Traefik derives the package name from the module path ("-" becomes "_").

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
)

const (
	headerXForwardedFor = "X-Forwarded-For"
	headerXRealIP       = "X-Real-Ip"
	headerForwarded     = "Forwarded"

	// MissingStrip removes the forwarding headers when a trusted peer sends no
	// valid client IP, so backends fall back to the peer address.
	MissingStrip = "strip"
	// MissingReject answers 400 Bad Request instead.
	MissingReject = "reject"
)

// Config is the plugin configuration.
type Config struct {
	// TrustedCIDRs lists the peers (by TCP source address, as Traefik sees it)
	// whose SourceHeader is believed. Required: with no trusted peers the
	// plugin only strips headers.
	TrustedCIDRs []string `json:"trustedCIDRs,omitempty" yaml:"trustedCIDRs,omitempty" toml:"trustedCIDRs,omitempty"`
	// SourceHeader holds the client IP set by the trusted upstream.
	// Default "CF-Connecting-IP".
	SourceHeader string `json:"sourceHeader,omitempty" yaml:"sourceHeader,omitempty" toml:"sourceHeader,omitempty"`
	// RewriteRemoteAddr also sets the request's remote address to the client IP,
	// so Traefik's access log, IP allow lists and its own X-Forwarded-For append
	// all see the real client. Default true.
	RewriteRemoteAddr *bool `json:"rewriteRemoteAddr,omitempty" yaml:"rewriteRemoteAddr,omitempty" toml:"rewriteRemoteAddr,omitempty"`
	// StripUntrusted removes SourceHeader, X-Forwarded-For, X-Real-Ip and
	// Forwarded from requests that do not come from a trusted peer. Default true.
	StripUntrusted *bool `json:"stripUntrusted,omitempty" yaml:"stripUntrusted,omitempty" toml:"stripUntrusted,omitempty"`
	// OnMissing says what to do when a trusted peer sends no valid client IP:
	// "strip" (default) or "reject".
	OnMissing string `json:"onMissing,omitempty" yaml:"onMissing,omitempty" toml:"onMissing,omitempty"`
}

// CreateConfig returns the default configuration.
func CreateConfig() *Config {
	return &Config{
		SourceHeader: "CF-Connecting-IP",
		OnMissing:    MissingStrip,
	}
}

// TrustedClientIP is the middleware.
type TrustedClientIP struct {
	next              http.Handler
	name              string
	trusted           []*net.IPNet
	sourceHeader      string
	rewriteRemoteAddr bool
	stripUntrusted    bool
	rejectMissing     bool
}

// New builds the middleware.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}

	m := &TrustedClientIP{
		next:              next,
		name:              name,
		sourceHeader:      http.CanonicalHeaderKey(strings.TrimSpace(config.SourceHeader)),
		rewriteRemoteAddr: boolOr(config.RewriteRemoteAddr, true),
		stripUntrusted:    boolOr(config.StripUntrusted, true),
	}
	if m.sourceHeader == "" {
		m.sourceHeader = "Cf-Connecting-Ip"
	}

	switch strings.ToLower(strings.TrimSpace(config.OnMissing)) {
	case "", MissingStrip:
	case MissingReject:
		m.rejectMissing = true
	default:
		return nil, fmt.Errorf("%s: onMissing must be %q or %q, got %q", name, MissingStrip, MissingReject, config.OnMissing)
	}

	for _, raw := range config.TrustedCIDRs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("%s: invalid trusted address %q", name, raw)
			}
			if ip.To4() != nil {
				s += "/32"
			} else {
				s += "/128"
			}
		}
		_, cidr, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid trusted CIDR %q: %w", name, raw, err)
		}
		m.trusted = append(m.trusted, cidr)
	}

	return m, nil
}

func (m *TrustedClientIP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !m.isTrustedPeer(req.RemoteAddr) {
		if m.stripUntrusted {
			req.Header.Del(m.sourceHeader)
			req.Header.Del(headerXForwardedFor)
			req.Header.Del(headerXRealIP)
			req.Header.Del(headerForwarded)
		}
		m.next.ServeHTTP(rw, req)
		return
	}

	clientIP := parseClientIP(req.Header.Get(m.sourceHeader))
	if clientIP == nil {
		if m.rejectMissing {
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		req.Header.Del(headerXForwardedFor)
		req.Header.Del(headerXRealIP)
		req.Header.Del(headerForwarded)
		m.next.ServeHTTP(rw, req)
		return
	}

	ip := clientIP.String()
	req.Header.Set(headerXForwardedFor, ip)
	req.Header.Set(headerXRealIP, ip)
	// Forwarded (RFC 7239) could carry another client-chosen "for=", and
	// nothing here rewrites it faithfully, so drop it.
	req.Header.Del(headerForwarded)

	if m.rewriteRemoteAddr {
		port := "0"
		if _, p, err := net.SplitHostPort(req.RemoteAddr); err == nil && p != "" {
			port = p
		}
		req.RemoteAddr = net.JoinHostPort(ip, port)
	}

	m.next.ServeHTTP(rw, req)
}

func (m *TrustedClientIP) isTrustedPeer(remoteAddr string) bool {
	if len(m.trusted) == 0 {
		return false
	}
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range m.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseClientIP accepts exactly one IP address (no list, no port, no zone).
func parseClientIP(v string) net.IP {
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, ",% ") {
		return nil
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func boolOr(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}
