package db

import (
	"path/filepath"
	"testing"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := d.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestNodeCRUDAndTokenLookup(t *testing.T) {
	d := openTestDB(t)
	id, err := d.CreateNode("edge-1", HashToken("tok-abc"))
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	n, err := d.GetNodeByTokenHash(HashToken("tok-abc"))
	if err != nil || n == nil {
		t.Fatalf("GetNodeByTokenHash: %+v %v", n, err)
	}
	if n.ID != id || n.Name != "edge-1" {
		t.Fatalf("node mismatch: %+v", n)
	}
	if bad, _ := d.GetNodeByTokenHash(HashToken("nope")); bad != nil {
		t.Fatalf("wrong token matched a node: %+v", bad)
	}
	// DeleteNode cascades to group_targets via the FK (no orphan targets).
	if err := d.DeleteNode(id); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if got, _ := d.ListNodes(); len(got) != 0 {
		t.Fatalf("want 0 nodes after delete, got %+v", got)
	}
}

type wantRule struct {
	ip, proto, user string
	port            int
}

func TestDesiredStateForNode(t *testing.T) {
	d := openTestDB(t)
	uA, _ := d.CreateUser("alice", "s", false)
	uB, _ := d.CreateUser("bob", "s", false)
	gWeb, _ := d.CreateGroup("web", 8080, "tcp")
	gDb, _ := d.CreateGroup("db", 3306, "tcp")
	nodeA, _ := d.CreateNode("node-A", HashToken("ta"))
	nodeB, _ := d.CreateNode("node-B", HashToken("tb"))

	// web -> node-A:18080, node-B:8080 ; db -> node-A:3306
	for _, gt := range []struct {
		g, n  int64
		port  int
		proto string
	}{
		{gWeb, nodeA, 18080, "tcp"},
		{gWeb, nodeB, 8080, "tcp"},
		{gDb, nodeA, 3306, "tcp"},
	} {
		if err := d.AddGroupTarget(gt.g, gt.n, gt.port, gt.proto); err != nil {
			t.Fatalf("AddGroupTarget: %v", err)
		}
	}

	_ = d.AddMembership(uA, gWeb, true)
	_ = d.AddMembership(uA, gDb, true)
	_ = d.AddMembership(uB, gWeb, false) // disabled — must be excluded
	_ = d.SetUserIP(uA, "203.0.113.10")
	_ = d.SetUserIP(uB, "203.0.113.20")

	// node-A: alice web@18080 + alice db@3306 (bob disabled).
	a, err := d.DesiredStateForNode(nodeA)
	if err != nil {
		t.Fatalf("DesiredStateForNode A: %v", err)
	}
	if len(a) != 2 {
		t.Fatalf("node-A want 2 rules, got %d: %+v", len(a), a)
	}
	want := map[string]wantRule{
		"web": {"203.0.113.10", "tcp", "alice", 18080},
		"db":  {"203.0.113.10", "tcp", "alice", 3306},
	}
	for _, r := range a {
		w, ok := want[r.Group]
		if !ok || r.IP != w.ip || r.Port != w.port || r.Proto != w.proto || r.User != w.user {
			t.Errorf("node-A unexpected rule %+v", r)
		}
	}

	// node-B: alice web@8080 only.
	b, err := d.DesiredStateForNode(nodeB)
	if err != nil {
		t.Fatalf("DesiredStateForNode B: %v", err)
	}
	if len(b) != 1 || b[0].Group != "web" || b[0].Port != 8080 || b[0].User != "alice" || b[0].IP != "203.0.113.10" {
		t.Fatalf("node-B want [alice web 8080 @203.0.113.10], got %+v", b)
	}

	// Disabling alice's web membership empties node-B's desired state (no IP churn
	// needed — the projection reflects membership immediately).
	_ = d.SetMembershipEnabled(uA, gWeb, false)
	if b2, _ := d.DesiredStateForNode(nodeB); len(b2) != 0 {
		t.Fatalf("after disable, node-B want 0 rules, got %+v", b2)
	}
}
