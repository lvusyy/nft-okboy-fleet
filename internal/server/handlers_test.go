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
		AnomalyWindow: 3600, AnomalyMaxChanges: 5,
	}
	return &harness{t: t, d: d, be: be, srv: NewServer(d, firewall.NewManager(be, d, "nft-okboy"), cfg).Routes()}
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

	for i := 0; i < 10; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i+1) // a fresh IP each time: the per-IP throttle never trips
		path, method := "/api/admin/totp", "DELETE"
		if i%2 == 1 {
			path, method = "/api/admin/totp/enroll", "POST"
		}
		if w := h.do(method, path, "root", ip, `{"totp_code":"000000"}`); w.Code != http.StatusForbidden {
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
