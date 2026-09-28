package firewall

import (
	"errors"
	"testing"
)

// mergingMock behaves like ufw: one rule per (ip, port, proto) — adding a rule
// that differs only in its comment rewrites the existing rule's comment, and
// with it the rule's handle (ufw's is a hash of the comment and the match).
type mergingMock struct{ *MockBackend }

func (m mergingMock) MergesSameMatch() bool { return true }

func (m mergingMock) AddRule(ip string, port int, user, proto, group string) error {
	m.mu.Lock()
	for i, r := range m.rules {
		if r.IP == ip && r.Port == port && r.Proto == proto {
			m.rules[i].User, m.rules[i].Group = user, group
			m.rules[i].Comment = commentFor(m.prefix, user, group)
			m.rules[i].Handle = m.next
			m.next++
			m.Calls = append(m.Calls, "AddRule(merged) "+group+" "+endpoint(ip, port, proto))
			m.mu.Unlock()
			return nil
		}
	}
	m.mu.Unlock()
	return m.MockBackend.AddRule(ip, port, user, proto, group)
}

// failingMerge is a mergingMock on which adding a rule for one user fails.
type failingMerge struct {
	mergingMock
	user string
}

func (f failingMerge) AddRule(ip string, port int, user, proto, group string) error {
	if user == f.user {
		return errors.New("injected failure")
	}
	return f.mergingMock.AddRule(ip, port, user, proto, group)
}

// TestReconcileAllMergingBackend: two users behind one address in the same group
// share ufw's single rule. ReconcileAll must count it for both — not re-comment
// it on every pass — and must hand it over (not delete it) when one of them goes.
func TestReconcileAllMergingBackend(t *testing.T) {
	be := mergingMock{NewMockBackend("ufw-okboy")}
	alice := Rule{IP: "203.0.113.10", Port: 8080, Proto: "tcp", User: "alice", Group: "web"}
	bob := Rule{IP: "203.0.113.10", Port: 8080, Proto: "tcp", User: "bob", Group: "web"}
	both := []Rule{alice, bob}
	if _, _, err := ReconcileAll(be, both); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if a, r, err := ReconcileAll(be, both); err != nil || a != 0 || r != 0 {
			t.Fatalf("pass %d with a shared rule: +%d/-%d (err %v), want no change", i+2, a, r, err)
		}
	}
	// The user whose comment the rule carries goes away: the rule stays, for bob.
	rules, _ := be.ListManaged()
	if len(rules) != 1 {
		t.Fatalf("want the one shared rule, got %+v", rules)
	}
	keep := alice
	if rules[0].User == "alice" {
		keep = bob
	}
	if _, _, err := ReconcileAll(be, []Rule{keep}); err != nil {
		t.Fatal(err)
	}
	if rules, _ = be.ListManaged(); len(rules) != 1 || rules[0].User != keep.User {
		t.Fatalf("after one user left: %+v, want one rule for %s", rules, keep.User)
	}

	// A failed add covers nothing: the other user sharing the match still gets it.
	fb := failingMerge{mergingMock{NewMockBackend("ufw-okboy")}, "alice"}
	if added, _, err := ReconcileAll(fb, both); err == nil || added != 1 {
		t.Fatalf("want +1 and the injected error, got +%d (err %v)", added, err)
	}
	if rules, _ = fb.ListManaged(); len(rules) != 1 || rules[0].User != "bob" {
		t.Fatalf("after alice's add failed: %+v, want bob's rule", rules)
	}
}

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
