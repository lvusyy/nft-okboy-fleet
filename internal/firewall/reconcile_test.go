package firewall

import "testing"

// TestReconcileAll: missing rules are added, rules no longer desired and
// duplicates are removed, and a second pass changes nothing.
func TestReconcileAll(t *testing.T) {
	be := NewMockBackend("nft-okboy")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(be.AddRule("198.51.100.9", 22, "ghost", "tcp", "ssh"))   // orphan (user gone)
	must(be.AddRule("203.0.113.10", 8080, "alice", "tcp", "web")) // desired
	must(be.AddRule("203.0.113.10", 8080, "alice", "tcp", "web")) // duplicate of it
	must(be.AddRule("203.0.113.99", 8080, "alice", "tcp", "web")) // alice's old IP
	desired := []Rule{
		{IP: "203.0.113.10", Port: 8080, Proto: "tcp", User: "alice", Group: "web"},
		{IP: "203.0.113.11", Port: 53, Proto: "udp", User: "bob", Group: "dns"},
	}
	added, removed, err := ReconcileAll(be, desired)
	if err != nil || added != 1 || removed != 3 {
		t.Fatalf("want +1/-3, got +%d/-%d (err %v)", added, removed, err)
	}
	got := liveSet(t, be)
	want := map[ruleKey]bool{
		{"203.0.113.10", 8080, "tcp", "alice", "web"}: true,
		{"203.0.113.11", 53, "udp", "bob", "dns"}:     true,
	}
	if len(got) != len(want) {
		t.Fatalf("live set %v, want %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("missing %v in %v", k, got)
		}
	}
	if rules, _ := be.ListManaged(); len(rules) != 2 {
		t.Fatalf("duplicates must be gone, got %+v", rules)
	}
	if a, r, _ := ReconcileAll(be, desired); a != 0 || r != 0 {
		t.Fatalf("second pass not idempotent: +%d/-%d", a, r)
	}
}
