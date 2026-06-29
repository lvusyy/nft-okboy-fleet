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
	"os/exec"
	"testing"
)

func TestNftIntegration(t *testing.T) {
	const table = "okboy_it" // isolated test table name; never collides with host rules

	be, err := NewNftBackend(NftConfig{Prefix: "okboy", Table: table, Chain: "input", Priority: -150})
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
