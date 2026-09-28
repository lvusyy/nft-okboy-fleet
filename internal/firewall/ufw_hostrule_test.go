package firewall

import (
	"errors"
	"strings"
	"testing"
)

// A real `ufw status numbered` listing (ufw 0.36, C locale; trailing blanks
// trimmed) with host rules of every shape the host-rule check must tell apart,
// plus two lines in the same format whose comments carry a prefix.
const hostRuleListing = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH
[ 2] 2222/tcp                   DENY IN     198.51.100.77              # host-deny
[ 3] 2223/tcp                   ALLOW IN    198.51.100.78              (log) # host-allow
[ 4] 2224/tcp                   ALLOW IN    198.51.100.79              # okboy:alice:g
[ 5] 2225/udp                   ALLOW IN    198.51.100.80
[ 6] 10.0.0.1 2226/tcp          ALLOW IN    198.51.100.81
[ 7] 2227/tcp on lo             ALLOW IN    198.51.100.82
[ 8] 2230/tcp                   REJECT IN   198.51.100.84              (log-all)
[ 9] 2231/tcp                   DENY IN     198.51.100.85 5555/tcp     # sport
[10] 2232                       ALLOW IN    198.51.100.86              # anyproto
[11] 2234/tcp                   ALLOW FWD   198.51.100.88
[12] 198.51.100.89 2235/tcp     ALLOW OUT   Anywhere                   (out)
[13] 2236/tcp                   DENY IN     198.51.100.90 6666/tcp     (log)
[14] 22/tcp (v6)                ALLOW IN    Anywhere (v6)              # SSH
[15] 2228/tcp                   LIMIT IN    2001:db8::5                # host-v6
[16] 2229/tcp                   ALLOW IN    ::ffff:198.51.100.83
[17] 2237/tcp                   DENY IN     198.51.100.91              # okboy:mallory:g
[18] 2238/tcp                   ALLOW IN    198.51.100.92              # okboy-other:bob:g
`

func TestHostRuleFor(t *testing.T) {
	cases := []struct {
		ip     string
		port   int
		proto  string
		action string // "" = no host rule decides
	}{
		{"198.51.100.77", 2222, "tcp", "DENY"},   // a host DENY: adding ours would make it an ALLOW
		{"198.51.100.78", 2223, "tcp", "ALLOW"},  // logged host ALLOW with a comment
		{"198.51.100.79", 2224, "tcp", ""},       // ours (another user behind the same address)
		{"198.51.100.80", 2225, "tcp", ""},       // other protocol
		{"198.51.100.80", 2225, "udp", "ALLOW"},  // no comment at all
		{"198.51.100.81", 2226, "tcp", ""},       // names a destination address: another match
		{"198.51.100.82", 2227, "tcp", ""},       // bound to an interface: another match
		{"198.51.100.84", 2230, "tcp", "REJECT"}, // log-all
		{"198.51.100.85", 2231, "tcp", ""},       // a source port: another match
		{"198.51.100.86", 2232, "tcp", ""},       // no protocol: another match
		{"198.51.100.88", 2234, "tcp", ""},       // routed (FWD)
		{"198.51.100.89", 2235, "tcp", ""},       // outgoing
		{"198.51.100.90", 2236, "tcp", ""},       // a source port, logged
		{"2001:db8::5", 2228, "tcp", "LIMIT"},    // IPv6
		{"2001:0db8:0::5", 2228, "tcp", "LIMIT"}, // same address, other spelling
		{"198.51.100.83", 2229, "tcp", ""},       // ::ffff: mapped v6 is a separate rule
		{"198.51.100.77", 2222, "udp", ""},       // same address and port, other protocol
		{"203.0.113.1", 22, "tcp", ""},           // "from Anywhere" is another match
		{"198.51.100.91", 2237, "tcp", "DENY"},   // our prefix on a DENY: we only add ALLOW, so the host's
		{"198.51.100.92", 2238, "tcp", "ALLOW"},  // another instance's prefix (serve + agent on one host)
	}
	for _, c := range cases {
		got, ok := hostRuleFor(hostRuleListing, "okboy", c.ip, c.port, c.proto)
		if ok != (c.action != "") || got != c.action {
			t.Errorf("hostRuleFor(%s, %d/%s) = %q, %v; want %q", c.ip, c.port, c.proto, got, ok, c.action)
		}
	}
}

func TestUfwInactive(t *testing.T) {
	if !ufwInactive("Status: inactive\n") {
		t.Error("inactive status not recognised")
	}
	if ufwInactive(hostRuleListing) {
		t.Error("active status read as inactive")
	}
}

// ufw is a Python program: it takes the language from LANGUAGE before LC_ALL, so
// a host LANGUAGE=zh_CN translated "Status: active" despite LC_ALL=C.
func TestUfwEnvForcesCLocale(t *testing.T) {
	t.Setenv("LANGUAGE", "zh_CN:zh")
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	last := map[string]string{} // exec keeps the last value of a repeated key
	for _, kv := range ufwEnv() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			last[k] = v
		}
	}
	for _, k := range []string{"LANG", "LC_ALL", "LANGUAGE"} {
		if last[k] != "C" {
			t.Errorf("%s = %q, want C", k, last[k])
		}
	}
}

// A rule the host's own rule decides is neither added nor an error, on every pass
// (not a "+1 repaired" every 30 seconds).
func TestReconcileAllLeavesHostRules(t *testing.T) {
	be := NewMockBackend(testPrefix)
	be.HostRules = map[string]string{"198.51.100.77:2222/tcp": "DENY"}
	desired := []Rule{
		{IP: "198.51.100.77", Port: 2222, Proto: "tcp", User: "alice", Group: "ssh"},
		{IP: "198.51.100.77", Port: 8080, Proto: "tcp", User: "alice", Group: "web"},
	}
	for pass := 1; pass <= 2; pass++ {
		added, removed, err := ReconcileAll(be, desired)
		want := 1
		if pass == 2 {
			want = 0
		}
		if err != nil || added != want || removed != 0 {
			t.Fatalf("pass %d: +%d/-%d err=%v, want +%d/-0 and no error", pass, added, removed, err, want)
		}
	}
}

// A host rule deciding access is not a failure; one that denies is reported, so
// the knock can say why the port stays closed (a host ALLOW lets the user in).
func TestManagerReconcileHostRuleIsNotAFailure(t *testing.T) {
	be := NewMockBackend(testPrefix)
	be.HostRules = map[string]string{"198.51.100.77:2222/tcp": "DENY", "198.51.100.77:2223/tcp": "ALLOW"}
	m := NewManager(be, nil, testPrefix)
	added, _, denied, err := m.Reconcile("alice", "198.51.100.77", map[string]PortProto{
		"ssh": {Port: 2222, Proto: "tcp"}, "alt": {Port: 2223, Proto: "tcp"}, "web": {Port: 8080, Proto: "tcp"}})
	if err != nil {
		t.Fatalf("Reconcile: %v (a host rule deciding access is not a failure)", err)
	}
	if len(added) != 1 || added[0] != "web" {
		t.Fatalf("added = %v, want only web", added)
	}
	if len(denied) != 1 || denied[0] != "ssh" {
		t.Fatalf("denied = %v, want only ssh", denied)
	}
	if err := be.AddRule("198.51.100.77", 2222, "alice", "tcp", "ssh"); !errors.Is(err, ErrHostRule) {
		t.Fatalf("a *HostRuleError must satisfy errors.Is(err, ErrHostRule), got %v", err)
	}
}
