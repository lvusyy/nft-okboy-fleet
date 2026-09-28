package firewall

import "testing"

// TestCanonicalIP: exactly one IP literal passes (canonicalized); keywords,
// CIDRs, zones and hostnames — which ufw or nft would widen or resolve — do not.
func TestCanonicalIP(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":        "203.0.113.7",
		" 203.0.113.7 ":      "203.0.113.7",
		"2001:DB8:0::1":      "2001:db8::1",
		"::ffff:203.0.113.7": "203.0.113.7",
		"any":                "",
		"0.0.0.0/0":          "",
		"203.0.113.0/24":     "",
		"fe80::1%eth0":       "",
		"example.com":        "",
		"":                   "",
	}
	for in, want := range cases {
		if got := CanonicalIP(in); got != want {
			t.Errorf("CanonicalIP(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCheckRule: the backends refuse anything but one IP, a valid port and tcp/udp.
func TestCheckRule(t *testing.T) {
	if err := checkRule("203.0.113.7", 22, "tcp"); err != nil {
		t.Fatalf("valid rule refused: %v", err)
	}
	for _, c := range []struct {
		ip    string
		port  int
		proto string
	}{
		{"any", 22, "tcp"},
		{"0.0.0.0/0", 22, "tcp"},
		{"203.0.113.7", 0, "tcp"},
		{"203.0.113.7", 65536, "tcp"},
		{"203.0.113.7", 22, "any"},
	} {
		if err := checkRule(c.ip, c.port, c.proto); err == nil {
			t.Errorf("checkRule(%q, %d, %q) accepted", c.ip, c.port, c.proto)
		}
	}
}
