package firewall

import (
	"sort"
	"strings"
	"testing"
)

const testPrefix = "ufw-okboy"

// ruleKey is a comparable identity for a managed rule, used to assert the exact
// live rule set after a reconcile.
type ruleKey struct {
	IP    string
	Port  int
	Proto string
	User  string
	Group string
}

// liveSet snapshots the backend's managed rules as a key set.
func liveSet(t *testing.T, be *MockBackend) map[ruleKey]bool {
	t.Helper()
	rules, err := be.ListManaged()
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	out := make(map[ruleKey]bool, len(rules))
	for _, r := range rules {
		out[ruleKey{r.IP, r.Port, r.Proto, r.User, r.Group}] = true
	}
	return out
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func eqStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = sortedCopy(a), sortedCopy(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// seed installs a starting rule set directly via the backend (bypassing the
// Manager) so each test begins from a known firewall state.
func seed(t *testing.T, be *MockBackend, rules []ruleKey) {
	t.Helper()
	for _, r := range rules {
		if err := be.AddRule(r.IP, r.Port, r.User, r.Proto, r.Group); err != nil {
			t.Fatalf("seed AddRule: %v", err)
		}
	}
	be.Calls = nil // discard seeding noise so Calls reflects only the reconcile
}

// TestReconcile is the table-driven port of test_ip_lifecycle.py: it exercises
// the four core behaviours of Manager.Reconcile against an in-memory backend.
// Reconcile touches only the backend, so a nil *db.DB is safe here.
func TestReconcile(t *testing.T) {
	const user = "alice"
	web := PortProto{Port: 8080, Proto: "tcp"}
	dbg := PortProto{Port: 3306, Proto: "tcp"}
	api := PortProto{Port: 8080, Proto: "udp"} // same port as web, different proto/group

	tests := []struct {
		name        string
		seedRules   []ruleKey
		clientIP    string
		enabled     map[string]PortProto
		wantAdded   []string
		wantRemoved []string
		wantLive    map[ruleKey]bool
	}{
		{
			// (a) First knock: no prior rules → add a rule per enabled group at the IP.
			name:      "first knock adds enabled group rules",
			seedRules: nil,
			clientIP:  "203.0.113.10",
			enabled:   map[string]PortProto{"web": web},
			wantAdded: []string{"web"},
			wantLive: map[ruleKey]bool{
				{"203.0.113.10", 8080, "tcp", user, "web"}: true,
			},
		},
		{
			// (b) IP change: old-IP rules for enabled groups are removed and re-added
			//     at the new IP (the reconcile self-heals stale old-IP rules).
			name: "ip change removes old and adds new",
			seedRules: []ruleKey{
				{"203.0.113.10", 8080, "tcp", user, "web"},
			},
			clientIP:    "198.51.100.7",
			enabled:     map[string]PortProto{"web": web},
			wantAdded:   []string{"web"},
			wantRemoved: []string{"web"},
			wantLive: map[ruleKey]bool{
				{"198.51.100.7", 8080, "tcp", user, "web"}: true,
			},
		},
		{
			// (c) A disabled group's rule is removed (group no longer in enabled set).
			name: "disabled group rule is removed",
			seedRules: []ruleKey{
				{"203.0.113.10", 8080, "tcp", user, "web"},
				{"203.0.113.10", 3306, "tcp", user, "db"},
			},
			clientIP:    "203.0.113.10",
			enabled:     map[string]PortProto{"web": web}, // db dropped
			wantRemoved: []string{"db"},
			wantLive: map[ruleKey]bool{
				{"203.0.113.10", 8080, "tcp", user, "web"}: true,
			},
		},
		{
			// (d) Cross-group same-port rules don't clobber: web(8080/tcp) and
			//     api(8080/udp) coexist; reconciling both enabled is a no-op.
			name: "cross-group same-port no clobber",
			seedRules: []ruleKey{
				{"203.0.113.10", 8080, "tcp", user, "web"},
				{"203.0.113.10", 8080, "udp", user, "api"},
			},
			clientIP: "203.0.113.10",
			enabled:  map[string]PortProto{"web": web, "api": api},
			wantLive: map[ruleKey]bool{
				{"203.0.113.10", 8080, "tcp", user, "web"}: true,
				{"203.0.113.10", 8080, "udp", user, "api"}: true,
			},
		},
		{
			// Extra: enabling a second group while online (heartbeat) opens the new
			//        port without disturbing the existing rule.
			name: "heartbeat adds newly enabled group",
			seedRules: []ruleKey{
				{"203.0.113.10", 8080, "tcp", user, "web"},
			},
			clientIP:  "203.0.113.10",
			enabled:   map[string]PortProto{"web": web, "db": dbg},
			wantAdded: []string{"db"},
			wantLive: map[ruleKey]bool{
				{"203.0.113.10", 8080, "tcp", user, "web"}: true,
				{"203.0.113.10", 3306, "tcp", user, "db"}:  true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			be := NewMockBackend(testPrefix)
			seed(t, be, tc.seedRules)
			m := NewManager(be, nil, testPrefix)

			added, removed, err := m.Reconcile(user, tc.clientIP, tc.enabled)
			if err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if !eqStrs(added, tc.wantAdded) {
				t.Errorf("added = %v, want %v", added, tc.wantAdded)
			}
			if !eqStrs(removed, tc.wantRemoved) {
				t.Errorf("removed = %v, want %v", removed, tc.wantRemoved)
			}
			got := liveSet(t, be)
			if len(got) != len(tc.wantLive) {
				t.Errorf("live rule count = %d, want %d (got %v)", len(got), len(tc.wantLive), got)
			}
			for k := range tc.wantLive {
				if !got[k] {
					t.Errorf("missing expected live rule %+v", k)
				}
			}
			for k := range got {
				if !tc.wantLive[k] {
					t.Errorf("unexpected live rule %+v", k)
				}
			}
		})
	}
}

// TestReconcileIsIdempotent verifies a second identical reconcile is a no-op:
// nothing added, nothing removed, and the backend issues no Add/Delete ops.
func TestReconcileIsIdempotent(t *testing.T) {
	const user = "bob"
	be := NewMockBackend(testPrefix)
	m := NewManager(be, nil, testPrefix)
	enabled := map[string]PortProto{"web": {Port: 8080, Proto: "tcp"}}

	if _, _, err := m.Reconcile(user, "10.0.0.1", enabled); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	be.Calls = nil

	added, removed, err := m.Reconcile(user, "10.0.0.1", enabled)
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if len(added) != 0 || len(removed) != 0 {
		t.Errorf("idempotent reconcile changed rules: added=%v removed=%v", added, removed)
	}
	for _, c := range be.Calls {
		if strings.HasPrefix(c, "AddRule") || strings.HasPrefix(c, "DeleteByHandle") {
			t.Errorf("idempotent reconcile issued mutating op: %q", c)
		}
	}
}

// TestPreciseRemoveAcrossGroups confirms removing one group's rule leaves another
// group's same-ip/port rule untouched (the cross-group collision fix), exercised
// directly through Manager.RemoveRule.
func TestPreciseRemoveAcrossGroups(t *testing.T) {
	const user = "carol"
	be := NewMockBackend(testPrefix)
	// Two rules, same ip/port, different proto+group.
	if err := be.AddRule("1.2.3.4", 8080, user, "tcp", "web"); err != nil {
		t.Fatal(err)
	}
	if err := be.AddRule("1.2.3.4", 8080, user, "udp", "api"); err != nil {
		t.Fatal(err)
	}
	m := NewManager(be, nil, testPrefix)

	if err := m.RemoveRule("1.2.3.4", 8080, user, "tcp", "web"); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	rules, err := be.ListManaged()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 surviving rule, got %d: %+v", len(rules), rules)
	}
	if rules[0].Group != "api" || rules[0].Proto != "udp" {
		t.Errorf("wrong rule survived: %+v", rules[0])
	}
}
