package firewall

import "testing"

// A realistic `ufw status numbered` sample (ufw 0.36, C locale): two non-managed
// rules ([1] world-open SSH, [6] a foreign comment, [7] the v6 SSH shadow) plus
// four okboy-managed rules across v4/v6 and tcp/udp.
const ufwSample = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8080/tcp                   ALLOW IN    203.0.113.10               # ufw-okboy:alice:web
[ 3] 3306/tcp                   ALLOW IN    203.0.113.10               # ufw-okboy:alice:db
[ 4] 8080/udp                   ALLOW IN    203.0.113.10               # ufw-okboy:alice:api
[ 5] 443/tcp                    ALLOW IN    2001:db8::1                # ufw-okboy:bob:https
[ 6] 80/tcp                     ALLOW IN    198.51.100.9               # someone-elses-note
[ 7] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
`

func TestParseUfwStatus(t *testing.T) {
	lines := parseUfwStatus("ufw-okboy", ufwSample)
	if len(lines) != 4 {
		t.Fatalf("want 4 managed rules, got %d: %+v", len(lines), lines)
	}
	by := map[string]ufwLine{}
	for _, ln := range lines {
		by[ln.r.Comment] = ln
	}
	cases := []struct {
		comment, ip, proto, user, group string
		num, port                       int
	}{
		{"ufw-okboy:alice:web", "203.0.113.10", "tcp", "alice", "web", 2, 8080},
		{"ufw-okboy:alice:db", "203.0.113.10", "tcp", "alice", "db", 3, 3306},
		{"ufw-okboy:alice:api", "203.0.113.10", "udp", "alice", "api", 4, 8080},
		{"ufw-okboy:bob:https", "2001:db8::1", "tcp", "bob", "https", 5, 443},
	}
	for _, c := range cases {
		ln, ok := by[c.comment]
		if !ok {
			t.Errorf("missing managed rule %s", c.comment)
			continue
		}
		if ln.num != c.num || ln.r.IP != c.ip || ln.r.Port != c.port ||
			ln.r.Proto != c.proto || ln.r.User != c.user || ln.r.Group != c.group {
			t.Errorf("rule %s parsed wrong: num=%d %+v (want num=%d ip=%s port=%d proto=%s user=%s group=%s)",
				c.comment, ln.num, ln.r, c.num, c.ip, c.port, c.proto, c.user, c.group)
		}
	}
}

func TestParseUfwStatusSkipsNonManaged(t *testing.T) {
	for _, ln := range parseUfwStatus("ufw-okboy", ufwSample) {
		if ln.r.Comment == "someone-elses-note" || ln.r.Comment == "" {
			t.Errorf("parser kept a non-managed rule: %+v", ln)
		}
	}
}

// A v6 source rule that carries the "(v6)" tag in the To column must still parse.
func TestParseUfwStatusV6Tag(t *testing.T) {
	const sample = `Status: active

[ 8] 8443/tcp (v6)             ALLOW IN    2001:db8::99               # ufw-okboy:carol:secure
`
	lines := parseUfwStatus("ufw-okboy", sample)
	if len(lines) != 1 {
		t.Fatalf("want 1 rule, got %d: %+v", len(lines), lines)
	}
	r := lines[0].r
	if r.IP != "2001:db8::99" || r.Port != 8443 || r.Proto != "tcp" || r.User != "carol" || r.Group != "secure" {
		t.Errorf("v6-tagged rule parsed wrong: %+v", r)
	}
}

func TestParseUfwStatusInactive(t *testing.T) {
	if got := parseUfwStatus("ufw-okboy", "Status: inactive\n"); len(got) != 0 {
		t.Errorf("inactive ufw should yield no rules, got %+v", got)
	}
}

func TestSynthHandleStableAndDistinct(t *testing.T) {
	h1 := synthHandle("ufw-okboy:alice:web", "203.0.113.10", 8080, "tcp")
	if h1 != synthHandle("ufw-okboy:alice:web", "203.0.113.10", 8080, "tcp") {
		t.Errorf("handle not deterministic")
	}
	if h1 <= 0 {
		t.Errorf("handle must be positive, got %d", h1)
	}
	// Same ip/port, different proto+group (the cross-group case) => different handle.
	if h1 == synthHandle("ufw-okboy:alice:api", "203.0.113.10", 8080, "udp") {
		t.Errorf("distinct rules collided on handle %d", h1)
	}
}
