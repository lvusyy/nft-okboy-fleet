package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nft-okboy-fleet/internal/auth"
	"nft-okboy-fleet/internal/config"
	"nft-okboy-fleet/internal/db"
	"nft-okboy-fleet/internal/firewall"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// harness is a Server over a real temp SQLite DB and an in-memory firewall.
type harness struct {
	t   *testing.T
	d   *db.DB
	be  *firewall.MockBackend
	cfg *config.Config
	s   *Server
	srv http.Handler
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	be := firewall.NewMockBackend("nft-okboy")
	cfg := &config.Config{
		SignatureTTL: 300, TrustedProxies: []string{"127.0.0.1"}, RulePrefix: "nft-okboy",
		ThrottleMaxFailures: 10, ThrottleWindow: 300, TOTPReplayProtection: true,
		AnomalyWindow: 3600, AnomalyMaxChanges: 5, NftGuard: true, CleanupMaxAgeDays: 7,
	}
	s := NewServer(d, firewall.NewManager(be, d, "nft-okboy"), cfg)
	return &harness{t: t, d: d, be: be, cfg: cfg, s: s, srv: s.Routes()}
}

func (h *harness) user(name string, admin bool) int64 {
	h.t.Helper()
	id, err := h.d.CreateUser(name, testSecret, admin)
	if err != nil {
		h.t.Fatal(err)
	}
	return id
}

// do sends an HMAC-signed request as user, arriving via the trusted proxy with
// the given X-Real-IP.
func (h *harness) do(method, path, user, realIP, body string) *httptest.ResponseRecorder {
	h.t.Helper()
	ts := fmt.Sprint(time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(user + ":" + ts))
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("X-Real-IP", realIP)
	r.Header.Set("Authorization", "HMAC-SHA256 "+user+":"+ts+":"+hex.EncodeToString(mac.Sum(nil)))
	w := httptest.NewRecorder()
	h.srv.ServeHTTP(w, r)
	return w
}

// TestKnockRefusesNonAddress: a proxy header that is not one IP ("any", a CIDR)
// must never reach the firewall — ufw would read it as "everyone".
func TestKnockRefusesNonAddress(t *testing.T) {
	h := newHarness(t)
	uid := h.user("alice", false)
	gid, _ := h.d.CreateGroup("web", 8080, "tcp")
	_ = h.d.AddMembership(uid, gid, true)

	for _, bad := range []string{"any", "0.0.0.0/0", "::1"} {
		if w := h.do("POST", "/api/knock", "alice", bad, ""); w.Code != http.StatusBadRequest {
			t.Errorf("X-Real-IP %q: want 400, got %d %s", bad, w.Code, w.Body)
		}
	}
	if rules, _ := h.be.ListManaged(); len(rules) != 0 {
		t.Fatalf("no rule may be added for a non-address, got %+v", rules)
	}
	if w := h.do("POST", "/api/knock", "alice", "203.0.113.7", ""); w.Code != http.StatusOK {
		t.Fatalf("valid knock: want 200, got %d %s", w.Code, w.Body)
	}
	if rules, _ := h.be.ListManaged(); len(rules) != 1 || rules[0].IP != "203.0.113.7" {
		t.Fatalf("want one rule for 203.0.113.7, got %+v", rules)
	}
}

// TestKnockWhileFirewallInactive: with ufw disabled no local rule changes, yet
// the knock is recorded (a hub's nodes need it) with a warning, and Maintain
// applies it once ufw is enabled.
func TestKnockWhileFirewallInactive(t *testing.T) {
	h := newHarness(t)
	uid := h.user("alice", false)
	gid, _ := h.d.CreateGroup("web", 8080, "tcp")
	_ = h.d.AddMembership(uid, gid, true)

	h.be.Inactive = true
	for _, what := range []string{"first knock", "heartbeat"} {
		w := h.do("POST", "/api/knock", "alice", "203.0.113.7", "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "not active") {
			t.Fatalf("%s with ufw inactive: want 200 with a warning, got %d %s", what, w.Code, w.Body)
		}
	}
	if u, _ := h.d.GetUser(uid); u.CurrentIP == nil || *u.CurrentIP != "203.0.113.7" {
		t.Fatal("the knock must be recorded while ufw is inactive")
	}
	h.s.Maintain() // still inactive: nothing to do, nothing to log as a failure

	h.be.Inactive = false
	h.s.Maintain()
	if got := h.groupRules(); len(got) != 1 || got["alice/web"] != "203.0.113.7" {
		t.Fatalf("after ufw is enabled Maintain must apply the knock, got %v", got)
	}
	if w := h.do("POST", "/api/knock", "alice", "203.0.113.7", ""); strings.Contains(w.Body.String(), "warning") {
		t.Fatalf("no warning once ufw is active: %s", w.Body)
	}
}

// TestKnockReportsHostDeny: a rule of the host's own that denies the caller on a
// group's port is left alone, and the knock says so instead of claiming the port.
func TestKnockReportsHostDeny(t *testing.T) {
	h := newHarness(t)
	uid := h.user("alice", false)
	ssh, _ := h.d.CreateGroup("ssh", 2222, "tcp")
	web, _ := h.d.CreateGroup("web", 8080, "tcp")
	_ = h.d.AddMembership(uid, ssh, true)
	_ = h.d.AddMembership(uid, web, true)
	h.be.HostRules = map[string]string{"203.0.113.7:2222/tcp": "DENY"}

	w := h.do("POST", "/api/knock", "alice", "203.0.113.7", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Group ssh (port 2222/tcp)") {
		t.Fatalf("knock: want 200 with a warning about ssh, got %d %s", w.Code, w.Body)
	}
	if got := h.groupRules(); len(got) != 1 || got["alice/web"] != "203.0.113.7" {
		t.Fatalf("only web may be opened, got %v", got)
	}
}

// TestRevokeRemovesRulesAtAnyAddress: a revoke removes the user's rules at every
// address, not only at the current one (a rule left at an earlier address would
// stay open), and warns when the firewall refuses the change.
func TestRevokeRemovesRulesAtAnyAddress(t *testing.T) {
	h := newHarness(t)
	h.user("root", true)
	uid := h.user("alice", false)
	gid, _ := h.d.CreateGroup("web", 8080, "tcp")
	_ = h.d.AddMembership(uid, gid, true)
	revoke := func() *httptest.ResponseRecorder {
		return h.do("POST", fmt.Sprintf("/api/admin/users/%d/revoke", uid), "root", "203.0.113.1", `{"rotate_secret": false}`)
	}

	if w := h.do("POST", "/api/knock", "alice", "203.0.113.7", ""); w.Code != http.StatusOK {
		t.Fatalf("knock: %d %s", w.Code, w.Body)
	}
	_ = h.be.AddRule("198.51.100.9", 8080, "alice", "tcp", "web") // left at an earlier address
	if w := revoke(); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "warning") {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if got := h.groupRules(); len(got) != 0 {
		t.Fatalf("a revoke must remove the user's rules at every address, left %v", got)
	}

	if w := h.do("POST", "/api/knock", "alice", "203.0.113.7", ""); w.Code != http.StatusOK {
		t.Fatalf("knock: %d %s", w.Code, w.Body)
	}
	h.be.Inactive = true
	if w := revoke(); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "firewall rule removal failed") {
		t.Fatalf("revoke with ufw inactive: want 200 with a warning, got %d %s", w.Code, w.Body)
	}
}

// TestDeleteGroupWarnsWhenRulesStay: a group deletion whose rules the firewall
// does not let go of is reported, not passed off as done.
func TestDeleteGroupWarnsWhenRulesStay(t *testing.T) {
	h := newHarness(t)
	h.user("root", true)
	uid := h.user("alice", false)
	gid, _ := h.d.CreateGroup("web", 8080, "tcp")
	_ = h.d.AddMembership(uid, gid, true)
	if w := h.do("POST", "/api/knock", "alice", "203.0.113.7", ""); w.Code != http.StatusOK {
		t.Fatalf("knock: %d %s", w.Code, w.Body)
	}
	h.be.Inactive = true
	w := h.do("DELETE", fmt.Sprintf("/api/admin/groups/%d", gid), "root", "203.0.113.1", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "firewall rule removal failed") {
		t.Fatalf("delete group with ufw inactive: want 200 with a warning, got %d %s", w.Code, w.Body)
	}
}

// TestMembershipRemovalWarnsWhenRulesStay: taking a group away (disabling one's
// own membership, an admin's removal) warns when the firewall keeps the rule.
func TestMembershipRemovalWarnsWhenRulesStay(t *testing.T) {
	h := newHarness(t)
	h.user("root", true)
	uid := h.user("alice", false)
	web, _ := h.d.CreateGroup("web", 8080, "tcp")
	pg, _ := h.d.CreateGroup("db", 5432, "tcp")
	_ = h.d.AddMembership(uid, web, true)
	_ = h.d.AddMembership(uid, pg, true)
	if w := h.do("POST", "/api/knock", "alice", "203.0.113.7", ""); w.Code != http.StatusOK {
		t.Fatalf("knock: %d %s", w.Code, w.Body)
	}
	h.be.Inactive = true
	w := h.do("PATCH", fmt.Sprintf("/api/me/membership/%d", pg), "alice", "203.0.113.7", `{"enabled":false}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "firewall rule removal failed") {
		t.Fatalf("disable own membership with ufw inactive: want 200 with a warning, got %d %s", w.Code, w.Body)
	}
	w = h.do("POST", "/api/admin/memberships/remove", "root", "203.0.113.1", `{"username":"alice","group_name":"web"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "firewall rule removal failed") {
		t.Fatalf("remove membership with ufw inactive: want 200 with a warning, got %d %s", w.Code, w.Body)
	}
}

// TestEnableGroupKeepsOtherGroups: re-enabling one group must not close the
// user's ports in their other enabled groups.
func TestEnableGroupKeepsOtherGroups(t *testing.T) {
	h := newHarness(t)
	uid := h.user("alice", false)
	web, _ := h.d.CreateGroup("web", 8080, "tcp")
	db2, _ := h.d.CreateGroup("db", 5432, "tcp")
	_ = h.d.AddMembership(uid, web, true)
	_ = h.d.AddMembership(uid, db2, false) // previously authorized, now disabled

	if w := h.do("POST", "/api/knock", "alice", "203.0.113.7", ""); w.Code != http.StatusOK {
		t.Fatalf("knock: %d %s", w.Code, w.Body)
	}
	w := h.do("PATCH", fmt.Sprintf("/api/me/membership/%d", db2), "alice", "203.0.113.7", `{"enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("enable db: %d %s", w.Code, w.Body)
	}
	got := map[string]bool{}
	rules, _ := h.be.ListManaged()
	for _, r := range rules {
		got[r.Group] = true
	}
	if !got["web"] || !got["db"] {
		t.Fatalf("both web and db must be open after enabling db, got %+v", rules)
	}
}

// TestTOTPGuessesCappedPerAccount: wrong codes on ANY TOTP endpoint, from any
// number of IPs, count toward one per-account cap; past it even a correct code is
// refused until the window passes.
func TestTOTPGuessesCappedPerAccount(t *testing.T) {
	h := newHarness(t)
	uid := h.user("root", true)
	seed := auth.GenerateTOTPSecret()
	_ = h.d.SetTOTPSecret(uid, seed)
	_ = h.d.EnableTOTP(uid)

	bad := wrongCode(seed)
	for i := 0; i < 10; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i+1) // a fresh IP each time: the per-IP throttle never trips
		path, method := "/api/admin/totp", "DELETE"
		if i%2 == 1 {
			path, method = "/api/admin/totp/enroll", "POST"
		}
		if w := h.do(method, path, "root", ip, `{"totp_code":"`+bad+`"}`); w.Code != http.StatusForbidden {
			t.Fatalf("guess %d: want 403, got %d %s", i, w.Code, w.Body)
		}
	}
	good := auth.TOTPNow(seed, time.Now().Unix())
	w := h.do("DELETE", "/api/admin/totp", "root", "198.51.100.99", `{"totp_code":"`+good+`"}`)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("after 10 failures want 429 even for a correct code, got %d %s", w.Code, w.Body)
	}
	if u, _ := h.d.GetUser(uid); !u.TOTPEnabled {
		t.Fatal("TOTP must still be enabled")
	}
}

// wrongCode returns a 6-digit code that is not valid for seed right now.
func wrongCode(seed string) string {
	now := time.Now().Unix()
	for _, c := range []string{"000000", "111111", "222222"} {
		if c != auth.TOTPNow(seed, now-30) && c != auth.TOTPNow(seed, now) && c != auth.TOTPNow(seed, now+30) {
			return c
		}
	}
	panic("unreachable")
}

func totpAdmin(t *testing.T, h *harness) string {
	t.Helper()
	uid := h.user("root", true)
	seed := auth.GenerateTOTPSecret()
	_ = h.d.SetTOTPSecret(uid, seed)
	_ = h.d.EnableTOTP(uid)
	return seed
}

// TestTOTPMissingCodeNotCounted: a write sent without a code (how the console
// learns that one is needed) is answered 403 totp_required but is not a guess —
// many of them must not lock the admin out.
func TestTOTPMissingCodeNotCounted(t *testing.T) {
	h := newHarness(t)
	seed := totpAdmin(t, h)
	for i := 0; i < 15; i++ {
		w := h.do("POST", "/api/admin/groups", "root", "198.51.100.1", fmt.Sprintf(`{"name":"g%d","port":%d}`, i, 2000+i))
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "totp_required") {
			t.Fatalf("request %d without a code: want 403 totp_required, got %d %s", i, w.Code, w.Body)
		}
	}
	good := auth.TOTPNow(seed, time.Now().Unix())
	if w := h.do("POST", "/api/admin/groups", "root", "198.51.100.1", `{"name":"web","port":8080,"totp_code":"`+good+`"}`); w.Code != http.StatusCreated {
		t.Fatalf("with a correct code after 15 code-less requests: want 201, got %d %s", w.Code, w.Body)
	}
}

// TestTOTPCapHoldsUnderConcurrency: guesses fired at once cannot all pass the
// cap check before any failure is counted — exactly ThrottleMaxFailures of them
// get to be checked, the rest are refused with 429.
func TestTOTPCapHoldsUnderConcurrency(t *testing.T) {
	h := newHarness(t)
	seed := totpAdmin(t, h)
	bad := wrongCode(seed)
	const n = 30
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes <- h.do("DELETE", "/api/admin/totp", "root", fmt.Sprintf("198.51.100.%d", i+1), `{"totp_code":"`+bad+`"}`).Code
		}(i)
	}
	wg.Wait()
	close(codes)
	checked := 0
	for c := range codes {
		switch c {
		case http.StatusForbidden:
			checked++
		case http.StatusTooManyRequests:
		default:
			t.Fatalf("unexpected status %d", c)
		}
	}
	if checked != 10 {
		t.Fatalf("%d of %d concurrent guesses were checked, want exactly 10", checked, n)
	}
}
