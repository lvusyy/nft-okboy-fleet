//go:build linux && integration

// Real-ufw integration test for UfwBackend. Gated behind the `integration` build
// tag (and linux) so the normal `go test ./...` stays hermetic. It MUST run
// inside a sandbox where ufw is ENABLED and /etc/ufw is a private throwaway copy
// — see scripts/ufw-integration.sh, which sets up a mount+net namespace and
// enables ufw before invoking this binary, so the host firewall is never touched:
//
//	GOOS=linux GOARCH=amd64 go test -tags integration -c -o nft-okboy-ufwtest ./internal/firewall/
//	sudo bash scripts/ufw-integration.sh ./nft-okboy-ufwtest
//
// Cross-group note: UFW deduplicates rules by match params (ip/port/proto) and
// IGNORES the comment, so two groups sharing the SAME (port, proto) for one user
// cannot coexist as distinct ufw rules. The cross-group case therefore uses
// different protos (22/tcp vs 22/udp) — exactly what Manager.Reconcile exercises.
package firewall

import "testing"

func TestUfwIntegration(t *testing.T) {
	const prefix = "okboy-it"
	be, err := NewUfwBackend(UfwConfig{Prefix: prefix})
	if err != nil {
		t.Fatalf("NewUfwBackend: %v", err)
	}

	// Remove any managed rules left by a crashed run, and clean up on exit.
	cleanup := func() {
		rules, _ := be.ListManaged()
		for _, r := range rules {
			_ = be.DeleteByHandle(r.Handle)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	// EnsureBase must succeed (ufw is active in the sandbox) and be idempotent.
	if err := be.EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	if err := be.EnsureBase(); err != nil {
		t.Fatalf("EnsureBase not idempotent: %v", err)
	}

	// Add a rule and read it back with a (synthetic) handle.
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
	if r := rules[0]; r.IP != "203.0.113.10" || r.Port != 22 || r.Proto != "tcp" ||
		r.User != "alice" || r.Group != "ssh" || r.Handle <= 0 {
		t.Fatalf("rule round-trip mismatch: %+v", r)
	}

	// Cross-group same-port (22) with different protos + a second port. Three
	// rules for alice: 22/tcp ssh, 22/udp admin, 8080/tcp web.
	if err := be.AddRule("203.0.113.10", 22, "alice", "udp", "admin"); err != nil {
		t.Fatalf("AddRule admin: %v", err)
	}
	if err := be.AddRule("203.0.113.20", 8080, "alice", "tcp", "web"); err != nil {
		t.Fatalf("AddRule web: %v", err)
	}
	if rules, _ = be.ListUserRules("alice"); len(rules) != 3 {
		t.Fatalf("want 3 rules, got %d: %+v", len(rules), rules)
	}

	// Precise delete: remove ssh on 22/tcp; admin on the SAME port (22/udp) must
	// survive — the cross-group-no-clobber guarantee.
	if err := be.RemoveRule("203.0.113.10", 22, "alice", "tcp", "ssh"); err != nil {
		t.Fatalf("RemoveRule ssh: %v", err)
	}
	rules, _ = be.ListUserRules("alice")
	if len(rules) != 2 {
		t.Fatalf("after precise delete want 2, got %d: %+v", len(rules), rules)
	}
	got := map[string]int64{}
	for _, r := range rules {
		got[r.Group] = r.Handle
	}
	if _, ok := got["ssh"]; ok {
		t.Fatalf("ssh should be gone after precise delete: %+v", rules)
	}
	if _, ok := got["admin"]; !ok {
		t.Fatalf("admin should survive precise delete: %+v", rules)
	}

	// DeleteByHandle: drop admin by its (re-resolved) handle; web survives.
	if err := be.DeleteByHandle(got["admin"]); err != nil {
		t.Fatalf("DeleteByHandle admin: %v", err)
	}
	if rules, _ = be.ListUserRules("alice"); len(rules) != 1 || rules[0].Group != "web" {
		t.Fatalf("after DeleteByHandle want only web, got %+v", rules)
	}

	// IPv6 round-trip.
	if err := be.AddRule("2001:db8::1", 443, "bob", "tcp", "https"); err != nil {
		t.Fatalf("AddRule v6: %v", err)
	}
	if br, _ := be.ListUserRules("bob"); len(br) != 1 || br[0].IP != "2001:db8::1" || br[0].Port != 443 {
		t.Fatalf("v6 round-trip mismatch: %+v", br)
	}

	// ListManaged sees all remaining managed rules (alice web, bob https).
	all, err := be.ListManaged()
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ListManaged want 2, got %d: %+v", len(all), all)
	}
	t.Logf("real ufw validated: add / list(handle) / precise cross-group delete / DeleteByHandle / ipv6 / listmanaged — %d managed rules", len(all))
}
