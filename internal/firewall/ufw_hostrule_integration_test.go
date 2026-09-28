//go:build linux && integration

// Real-ufw checks for the host-rule and inactive-ufw handling; run like the rest
// of the ufw integration tests (scripts/ufw-integration.sh), never on a host.
package firewall

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// ufwRun runs one ufw command in the sandbox and returns its output.
func ufwRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ufw", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ufw %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// ufwEnable enables ufw and checks that it is active. The exit status is not
// trusted: ufw reports a failure when the kernel lacks an optional module (LOG,
// say) although the firewall is active.
func ufwEnable(t *testing.T) {
	t.Helper()
	_ = exec.Command("ufw", "--force", "enable").Run()
	if out := ufwRun(t, "status"); !strings.HasPrefix(out, "Status: active") {
		t.Fatalf("ufw not active after enable:\n%s", out)
	}
}

// TestUfwIntegrationHostRules: a host rule with the match of a managed rule is
// left in charge. Adding ours over it would make ufw rewrite it — its comment (a
// later revoke would then delete it as ours) and its action (DENY -> ALLOW).
func TestUfwIntegrationHostRules(t *testing.T) {
	const prefix = "okboy-host"
	be, err := NewUfwBackend(UfwConfig{Prefix: prefix})
	if err != nil {
		t.Fatalf("NewUfwBackend: %v", err)
	}
	hosts := [][]string{
		{"deny", "from", "198.51.100.77", "to", "any", "port", "2222", "proto", "tcp"},
		{"allow", "log", "from", "198.51.100.78", "to", "any", "port", "2223", "proto", "tcp"},
		// ufw keeps these apart from "from <ip> to any port <port> proto tcp":
		{"allow", "from", "::ffff:198.51.100.79", "to", "any", "port", "2224", "proto", "tcp"},
		{"deny", "from", "198.51.100.80", "port", "5555", "to", "any", "port", "2225", "proto", "tcp"},
	}
	// A host DENY whose comment carries our prefix: nft-okboy only adds ALLOW
	// rules, so it is the host's all the same.
	prefixed := []string{"deny", "from", "198.51.100.81", "to", "any", "port", "2226", "proto", "tcp"}
	t.Cleanup(func() {
		_ = exec.Command("ufw", append([]string{"delete"}, prefixed...)...).Run()
		for _, h := range hosts {
			_ = exec.Command("ufw", append([]string{"delete"}, h...)...).Run()
		}
		rules, _ := be.ListManaged()
		for _, r := range rules {
			_ = be.DeleteByHandle(r.Handle)
		}
	})
	for _, h := range hosts {
		ufwRun(t, append(h, "comment", "host-rule")...)
	}
	ufwRun(t, append(prefixed, "comment", prefix+":mallory:g")...)

	if err := be.AddRule("198.51.100.77", 2222, "alice", "tcp", "g"); !errors.Is(err, ErrHostRule) {
		t.Fatalf("AddRule over a host DENY: %v, want ErrHostRule", err)
	}
	if err := be.AddRule("198.51.100.78", 2223, "alice", "tcp", "g"); !errors.Is(err, ErrHostRule) {
		t.Fatalf("AddRule over a logged host ALLOW: %v, want ErrHostRule", err)
	}
	if err := be.AddRule("198.51.100.79", 2224, "alice", "tcp", "g"); err != nil {
		t.Fatalf("AddRule next to an IPv4-mapped IPv6 host rule: %v", err)
	}
	if err := be.AddRule("198.51.100.80", 2225, "alice", "tcp", "g"); err != nil {
		t.Fatalf("AddRule next to a host rule with a source port: %v", err)
	}
	if err := be.AddRule("198.51.100.81", 2226, "alice", "tcp", "g"); !errors.Is(err, ErrHostRule) {
		t.Fatalf("AddRule over a host DENY with our prefix: %v, want ErrHostRule", err)
	}

	status := ufwRun(t, "status", "numbered")
	if a, ok := hostRuleFor(status, prefix, "198.51.100.77", 2222, "tcp"); !ok || a != "DENY" {
		t.Fatalf("host DENY changed (%q, %v):\n%s", a, ok, status)
	}
	if !strings.Contains(status, "(log) # host-rule") {
		t.Fatalf("logged host ALLOW taken over:\n%s", status)
	}
	if got := strings.Count(status, "# host-rule"); got != len(hosts) {
		t.Fatalf("host rules: %d intact, want %d:\n%s", got, len(hosts), status)
	}
	managed, err := be.ListManaged()
	if err != nil || len(managed) != 2 {
		t.Fatalf("managed rules = %+v (err %v), want the two added beside host rules", managed, err)
	}

	desired := []Rule{
		{IP: "198.51.100.77", Port: 2222, Proto: "tcp", User: "alice", Group: "g"},
		{IP: "198.51.100.78", Port: 2223, Proto: "tcp", User: "alice", Group: "g"},
		{IP: "198.51.100.79", Port: 2224, Proto: "tcp", User: "alice", Group: "g"},
		{IP: "198.51.100.80", Port: 2225, Proto: "tcp", User: "alice", Group: "g"},
		{IP: "198.51.100.81", Port: 2226, Proto: "tcp", User: "alice", Group: "g"},
	}
	for pass := 1; pass <= 2; pass++ {
		if a, r, err := ReconcileAll(be, desired); err != nil || a != 0 || r != 0 {
			t.Fatalf("ReconcileAll pass %d: +%d/-%d err=%v, want no change", pass, a, r, err)
		}
	}
	// alice leaves: her two rules go, every host rule stays.
	if _, r, err := ReconcileAll(be, nil); err != nil || r != 2 {
		t.Fatalf("ReconcileAll(nil): -%d err=%v, want -2", r, err)
	}
	status = ufwRun(t, "status", "numbered")
	if got := strings.Count(status, "# host-rule"); got != len(hosts) {
		t.Fatalf("host rules after the user left: %d intact, want %d:\n%s", got, len(hosts), status)
	}
	if a, ok := hostRuleFor(status, prefix, "198.51.100.81", 2226, "tcp"); !ok || a != "DENY" {
		t.Fatalf("host DENY with our prefix changed or removed (%q, %v):\n%s", a, ok, status)
	}
}

// TestUfwIntegrationInactive: a disabled ufw lists no rules although it keeps
// them saved; nothing may pass for "there are no rules" then.
func TestUfwIntegrationInactive(t *testing.T) {
	be, err := NewUfwBackend(UfwConfig{Prefix: "okboy-off"})
	if err != nil {
		t.Fatalf("NewUfwBackend: %v", err)
	}
	t.Cleanup(func() {
		_ = exec.Command("ufw", "--force", "enable").Run() // the other tests need it on
		rules, _ := be.ListManaged()
		for _, r := range rules {
			_ = be.DeleteByHandle(r.Handle)
		}
	})
	if err := be.AddRule("203.0.113.60", 9660, "alice", "tcp", "g"); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	ufwRun(t, "--force", "disable")

	if _, err := be.ListManaged(); !errors.Is(err, ErrInactive) {
		t.Fatalf("ListManaged on a disabled ufw: %v, want ErrInactive", err)
	}
	if err := be.RemoveRule("203.0.113.60", 9660, "alice", "tcp", "g"); !errors.Is(err, ErrInactive) {
		t.Fatalf("RemoveRule on a disabled ufw: %v, want ErrInactive (it would pass for done)", err)
	}
	if err := be.AddRule("203.0.113.61", 9661, "alice", "tcp", "g"); !errors.Is(err, ErrInactive) {
		t.Fatalf("AddRule on a disabled ufw: %v, want ErrInactive", err)
	}
	if _, _, err := ReconcileAll(be, nil); !errors.Is(err, ErrInactive) {
		t.Fatalf("ReconcileAll on a disabled ufw: %v, want ErrInactive", err)
	}

	ufwEnable(t)
	rules, err := be.ListManaged()
	if err != nil || len(rules) != 1 || rules[0].IP != "203.0.113.60" {
		t.Fatalf("after enabling: %+v (err %v), want the rule kept while ufw was off", rules, err)
	}
}
