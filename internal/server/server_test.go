package server

import (
	"net/http/httptest"
	"testing"

	"nft-okboy-fleet/internal/config"
)

// TestClientIPOnlySingleAddresses: whatever a trusted proxy's headers carry, only
// one canonical IP literal comes out — "any" or a CIDR would make a ufw rule open
// the port to everyone. Anything else falls back to the peer (which the knock
// handler refuses as loopback).
func TestClientIPOnlySingleAddresses(t *testing.T) {
	s := NewServer(nil, nil, &config.Config{TrustedProxies: []string{"127.0.0.1"}})
	cases := []struct {
		peer, xri, xff, want string
	}{
		{"127.0.0.1:4000", "203.0.113.7", "", "203.0.113.7"},
		{"127.0.0.1:4000", " 2001:DB8::1 ", "", "2001:db8::1"},
		{"127.0.0.1:4000", "::ffff:203.0.113.7", "", "203.0.113.7"},
		{"127.0.0.1:4000", "any", "198.51.100.9", "127.0.0.1"},
		{"127.0.0.1:4000", "0.0.0.0/0", "", "127.0.0.1"},
		{"127.0.0.1:4000", "fe80::1%eth0", "", "127.0.0.1"},
		{"127.0.0.1:4000", "", "10.0.0.1, 203.0.113.9", "203.0.113.9"},
		{"127.0.0.1:4000", "", "203.0.113.9, any", "127.0.0.1"},
		{"198.51.100.1:5000", "203.0.113.7", "", "198.51.100.1"}, // untrusted peer: headers ignored
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/api/knock", nil)
		r.RemoteAddr = c.peer
		if c.xri != "" {
			r.Header.Set("X-Real-IP", c.xri)
		}
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := s.clientIP(r); got != c.want {
			t.Errorf("peer=%s X-Real-IP=%q XFF=%q: got %q, want %q", c.peer, c.xri, c.xff, got, c.want)
		}
	}
}

// TestRoutesRegister guards against a ServeMux pattern-conflict panic at route
// registration. Go 1.22's mux panics when two patterns overlap with neither being
// more specific — e.g. a "/api/" subtree catch-all conflicts with "GET /". Neither
// `go build` nor `go vet` calls Routes(), so a registration panic ships silently
// and only surfaces when `nft-okboy serve` crash-loops on startup. This test invokes
// the real registration path so `go test` catches the whole class of bug.
func TestRoutesRegister(t *testing.T) {
	// Route registration builds the mux and wraps it in the throttle gate; it does
	// not dereference db/fw, so nil deps are fine here (a non-nil cfg is passed for
	// safety since the gate closure captures it).
	s := NewServer(nil, nil, &config.Config{})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Routes() panicked while registering patterns: %v", r)
		}
	}()
	if s.Routes() == nil {
		t.Fatal("Routes() returned a nil handler")
	}
}
