//go:build linux && integration

// Real-nftables integration test for NftBackend. It is gated behind the
// `integration` build tag (and linux) so the normal `go test ./...` stays
// hermetic. Run it as root inside an isolated network namespace so it exercises
// real `nft` without touching the host/k8s firewall:
//
//	go test -tags integration -c -o /tmp/nfttest ./internal/firewall/
//	sudo ip netns add okboy_it_ns
//	sudo ip netns exec okboy_it_ns env PATH=/usr/sbin:/usr/bin:/bin \
//	    /tmp/nfttest -test.run TestNftIntegration -test.v
//	sudo ip netns del okboy_it_ns
package firewall

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestNftIntegration(t *testing.T) {
	const table = "okboy_it" // isolated test table name; never collides with host rules

	be, err := NewNftBackend(NftConfig{Prefix: "nft-okboy", Table: table, Chain: "input", Priority: -150})
	if err != nil {
		t.Fatalf("NewNftBackend: %v", err)
	}
	delTable := func() { _ = exec.Command("nft", "delete", "table", "inet", table).Run() }
	delTable() // pre-clean any leftover from a crashed run
	t.Cleanup(delTable)

	// EnsureBase must succeed and be idempotent.
	if err := be.EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	if err := be.EnsureBase(); err != nil {
		t.Fatalf("EnsureBase not idempotent: %v", err)
	}

	// Add a rule and read it back with a real handle.
	if err := be.AddRule("203.0.113.10", 22, "alice", "tcp", "ssh"); err != nil {
		t.Fatalf("AddRule ssh: %v", err)
	}
	rules, err := be.ListUserRules("alice")
	if err != nil {
		t.Fatalf("ListUserRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d: %+v", len(rules), rules)
	}
	if r := rules[0]; r.IP != "203.0.113.10" || r.Port != 22 || r.Proto != "tcp" || r.User != "alice" || r.Group != "ssh" || r.Handle <= 0 {
		t.Fatalf("rule round-trip mismatch: %+v", r)
	}

	// Cross-group same-port (22) + a second port. Three rules for alice.
	if err := be.AddRule("203.0.113.10", 22, "alice", "tcp", "admin"); err != nil {
		t.Fatalf("AddRule admin: %v", err)
	}
	if err := be.AddRule("203.0.113.20", 8080, "alice", "tcp", "web"); err != nil {
		t.Fatalf("AddRule web: %v", err)
	}
	if rules, _ = be.ListUserRules("alice"); len(rules) != 3 {
		t.Fatalf("want 3 rules, got %d: %+v", len(rules), rules)
	}

	// Precise delete: remove ssh on port 22; admin on the SAME port must survive
	// (the cross-group-no-clobber guarantee).
	if err := be.RemoveRule("203.0.113.10", 22, "alice", "tcp", "ssh"); err != nil {
		t.Fatalf("RemoveRule ssh: %v", err)
	}
	rules, _ = be.ListUserRules("alice")
	if len(rules) != 2 {
		t.Fatalf("after precise delete want 2, got %d: %+v", len(rules), rules)
	}
	got := map[string]bool{}
	for _, r := range rules {
		got[r.Group] = true
	}
	if got["ssh"] || !got["admin"] || !got["web"] {
		t.Fatalf("precise delete wrong; want {admin,web}, got %v (%+v)", got, rules)
	}

	// IPv6 round-trip.
	if err := be.AddRule("2001:db8::1", 443, "bob", "tcp", "https"); err != nil {
		t.Fatalf("AddRule v6: %v", err)
	}
	if br, _ := be.ListUserRules("bob"); len(br) != 1 || br[0].IP != "2001:db8::1" || br[0].Port != 443 {
		t.Fatalf("v6 round-trip mismatch: %+v", br)
	}

	// ListManaged sees all remaining managed rules (alice admin+web, bob https).
	all, err := be.ListManaged()
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ListManaged want 3, got %d: %+v", len(all), all)
	}
	t.Logf("real nftables validated: add/list(handle)/precise cross-group delete/ipv6/listmanaged — %d managed rules", len(all))
}

// TestNftIntegrationGuard: the guard sits at the chain's tail after every allow
// rule (AddRule inserts at the head), is invisible to ListManaged, is left alone
// when already right, is rebuilt when an allow rule ends up behind it, and goes
// away with an empty port set.
func TestNftIntegrationGuard(t *testing.T) {
	const table = "okboy_guard_it"
	be, err := NewNftBackend(NftConfig{Prefix: "nft-okboy", Table: table, Chain: "input", Priority: -150})
	if err != nil {
		t.Fatalf("NewNftBackend: %v", err)
	}
	delTable := func() { _ = exec.Command("nft", "delete", "table", "inet", table).Run() }
	delTable()
	t.Cleanup(delTable)
	if err := be.EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	if err := be.AddRule("203.0.113.10", 22, "alice", "tcp", "ssh"); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	ports := []PortProto{{22, "tcp"}, {53, "udp"}, {22, "tcp"}} // duplicate on purpose
	if err := be.SyncGuard(ports); err != nil {
		t.Fatalf("SyncGuard: %v", err)
	}

	// layout returns "allow" / "lo" / "<port>/<proto>" per rule in chain order.
	layout := func() []string {
		chain, err := be.listChain()
		if err != nil {
			t.Fatalf("listChain: %v", err)
		}
		var out []string
		for _, r := range chain {
			switch {
			case strings.HasPrefix(r.Comment, "nft-okboy:"):
				out = append(out, "allow")
			case r.Comment == "nft-okboy-guard" && r.Port == 0:
				out = append(out, "lo")
			case r.Comment == "nft-okboy-guard":
				out = append(out, fmt.Sprintf("%d/%s", r.Port, r.Proto))
			default:
				out = append(out, "?"+r.Comment)
			}
		}
		return out
	}
	want := func(exp ...string) {
		t.Helper()
		if got := layout(); strings.Join(got, " ") != strings.Join(exp, " ") {
			t.Fatalf("chain layout = %v, want %v", got, exp)
		}
	}
	want("allow", "lo", "22/tcp", "53/udp")
	if listing, _ := exec.Command("nft", "list", "chain", "inet", table, "input").Output(); !strings.Contains(string(listing), "tcp dport 22 tcp flags syn / syn,ack drop") || !strings.Contains(string(listing), `iif "lo" accept`) {
		t.Fatalf("guard rules not as intended:\n%s", listing)
	}
	if managed, _ := be.ListManaged(); len(managed) != 1 {
		t.Fatalf("guard rules must not show up as managed allow rules: %+v", managed)
	}

	// New allow rules go in front of the guard; an unchanged guard is not touched.
	before, _ := be.listChain()
	if err := be.AddRule("203.0.113.11", 53, "bob", "udp", "dns"); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if err := be.SyncGuard(ports); err != nil {
		t.Fatalf("SyncGuard: %v", err)
	}
	want("allow", "allow", "lo", "22/tcp", "53/udp")
	after, _ := be.listChain()
	if before[len(before)-1].Handle != after[len(after)-1].Handle {
		t.Fatal("an unchanged guard must not be rebuilt")
	}

	// An allow rule appended behind the guard (an older nft-okboy, a human) makes
	// the guard rebuild at the tail again.
	if out, err := exec.Command("nft", "add", "rule", "inet", table, "input", "ip", "saddr", "203.0.113.12",
		"tcp", "dport", "8080", "accept", "comment", `"nft-okboy:eve:web"`).CombinedOutput(); err != nil {
		t.Fatalf("append rule: %v: %s", err, out)
	}
	if err := be.SyncGuard(ports); err != nil {
		t.Fatalf("SyncGuard: %v", err)
	}
	want("allow", "allow", "allow", "lo", "22/tcp", "53/udp")

	// A changed port set and then an empty one.
	if err := be.SyncGuard([]PortProto{{8080, "tcp"}}); err != nil {
		t.Fatalf("SyncGuard: %v", err)
	}
	want("allow", "allow", "allow", "lo", "8080/tcp")
	if err := be.SyncGuard(nil); err != nil {
		t.Fatalf("SyncGuard(nil): %v", err)
	}
	want("allow", "allow", "allow")
}
