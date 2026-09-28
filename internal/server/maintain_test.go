package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nft-okboy-fleet/internal/db"
	"nft-okboy-fleet/internal/firewall"
)

func (h *harness) groupRules() map[string]string { // group -> ip
	h.t.Helper()
	rules, err := h.be.ListManaged()
	if err != nil {
		h.t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rules {
		out[r.User+"/"+r.Group] = r.IP
	}
	return out
}

// TestMaintainRepairsAndGuards: the periodic pass guards every group port,
// restores a rule lost from the firewall, removes an orphan, expires a user who
// stopped knocking, and drops the guard when nft_guard is off.
func TestMaintainRepairsAndGuards(t *testing.T) {
	h := newHarness(t)
	alice := h.user("alice", false)
	web, _ := h.d.CreateGroup("web", 8080, "tcp")
	_, _ = h.d.CreateGroup("dns", 53, "udp")
	_ = h.d.AddMembership(alice, web, true)
	if w := h.do("POST", "/api/knock", "alice", "203.0.113.7", ""); w.Code != http.StatusOK {
		t.Fatalf("knock: %d %s", w.Code, w.Body)
	}

	// Drift: alice's rule vanished (a flushed table) and an orphan appeared (a
	// user deleted while the delete of their rule failed).
	rules, _ := h.be.ListManaged()
	for _, r := range rules {
		_ = h.be.DeleteByHandle(r.Handle)
	}
	_ = h.be.AddRule("198.51.100.9", 8080, "ghost", "tcp", "web")

	h.s.Maintain()
	if got := h.groupRules(); len(got) != 1 || got["alice/web"] != "203.0.113.7" {
		t.Fatalf("after Maintain want only alice/web@203.0.113.7, got %v", got)
	}
	want := []firewall.PortProto{{Port: 8080, Proto: "tcp"}, {Port: 53, Proto: "udp"}}
	if len(h.be.Guarded) != 2 || !containsPP(h.be.Guarded, want[0]) || !containsPP(h.be.Guarded, want[1]) {
		t.Fatalf("guard = %+v, want %+v", h.be.Guarded, want)
	}

	// alice stops knocking for longer than cleanup_max_age_days.
	old := time.Now().Add(-8 * 24 * time.Hour).Unix()
	if _, err := h.d.Conn().Exec(`UPDATE users SET last_knock=? WHERE id=?`, old, alice); err != nil {
		t.Fatal(err)
	}
	h.s.lastCleanup = time.Time{} // due now
	h.s.Maintain()
	if got := h.groupRules(); len(got) != 0 {
		t.Fatalf("an idle user's rules must expire, got %v", got)
	}
	if u, _ := h.d.GetUser(alice); u.CurrentIP != nil {
		t.Fatalf("an idle user's IP must be cleared, got %v", *u.CurrentIP)
	}

	h.cfg.NftGuard = false
	h.s.Maintain()
	if h.be.Guarded != nil {
		t.Fatalf("nft_guard: false must remove the guard, got %+v", h.be.Guarded)
	}
}

func containsPP(ps []firewall.PortProto, p firewall.PortProto) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}

// TestDesiredStateReportsPorts: the node API lists the node's managed ports,
// also when no rule is due, so an nftables agent can guard them.
func TestDesiredStateReportsPorts(t *testing.T) {
	h := newHarness(t)
	nid, _ := h.d.CreateNode("edge", db.HashToken("tok"))
	web, _ := h.d.CreateGroup("web", 8080, "tcp")
	_ = h.d.AddGroupTarget(web, nid, 18080, "tcp")

	r := httptest.NewRequest("GET", "/api/v1/node/desired-state", nil)
	r.RemoteAddr = "198.51.100.1:5000"
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	h.srv.ServeHTTP(w, r)
	var body struct {
		Rules []any `json:"rules"`
		Ports []struct {
			Port  int    `json:"port"`
			Proto string `json:"proto"`
		} `json:"ports"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK {
		t.Fatalf("desired-state: %d %s", w.Code, w.Body)
	}
	if len(body.Rules) != 0 || len(body.Ports) != 1 || body.Ports[0].Port != 18080 || body.Ports[0].Proto != "tcp" {
		t.Fatalf("want no rules and ports [18080/tcp], got %s", w.Body)
	}
}
