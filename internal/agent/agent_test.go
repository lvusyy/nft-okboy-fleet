package agent

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nft-okboy-fleet/internal/firewall"
)

// TestClientTrustAndRedirects: a self-signed hub is trusted only through a
// pinned certificate (--ca), and a redirect is never followed with the token.
func TestClientTrustAndRedirects(t *testing.T) {
	hub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "http://attacker.example/steal", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"rules":[]}`))
	}))
	defer hub.Close()
	pinned := x509.NewCertPool()
	pinned.AddCert(hub.Certificate())
	ctx := context.Background()
	opts := Options{Token: "t", Interval: time.Second}

	if _, err := fetch(ctx, newClient(opts), hub.URL+"/state", opts); err == nil {
		t.Fatal("a self-signed hub must not be trusted without --ca")
	}
	opts.RootCAs = pinned
	if _, err := fetch(ctx, newClient(opts), hub.URL+"/state", opts); err != nil {
		t.Fatalf("pinned hub certificate rejected: %v", err)
	}
	if _, err := fetch(ctx, newClient(opts), hub.URL+"/moved", opts); err == nil {
		t.Fatal("a redirect must not be followed")
	}
}

func keyset(t *testing.T, be *firewall.MockBackend) map[string]bool {
	t.Helper()
	rules, err := be.ListManaged()
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	m := map[string]bool{}
	for _, r := range rules {
		m[r.IP+"|"+r.Proto+"|"+r.User+"|"+r.Group] = true
	}
	return m
}

// TestAgentReconcile drives the whole-node reconcile against an in-memory backend:
// a stale managed rule is dropped, the two desired rules are added, and a second
// pass is a no-op (idempotent) — the exact contract the agent loop relies on.
func TestAgentReconcile(t *testing.T) {
	be := firewall.NewMockBackend("nft-okboy")
	// A managed rule that is NO LONGER desired (e.g. the user's IP changed / left).
	if err := be.AddRule("198.51.100.9", 22, "carol", "tcp", "ssh"); err != nil {
		t.Fatal(err)
	}

	desired := []rule{
		{IP: "203.0.113.10", Port: 8080, Proto: "tcp", User: "alice", Group: "web"},
		{IP: "203.0.113.10", Port: 3306, Proto: "tcp", User: "alice", Group: "db"},
	}
	added, removed, err := Reconcile(be, desired)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if added != 2 || removed != 1 {
		t.Fatalf("want +2/-1, got +%d/-%d", added, removed)
	}
	got := keyset(t, be)
	if !got["203.0.113.10|tcp|alice|web"] || !got["203.0.113.10|tcp|alice|db"] {
		t.Errorf("desired rules missing: %v", got)
	}
	if got["198.51.100.9|tcp|carol|ssh"] {
		t.Errorf("stale rule not removed: %v", got)
	}

	// Idempotent: a second identical reconcile issues no mutations.
	if a2, r2, _ := Reconcile(be, desired); a2 != 0 || r2 != 0 {
		t.Errorf("second reconcile not idempotent: +%d/-%d", a2, r2)
	}

	// Empty desired set removes everything managed (e.g. node de-targeted).
	a3, r3, _ := Reconcile(be, nil)
	if a3 != 0 || r3 != 2 {
		t.Errorf("clear-out want +0/-2, got +%d/-%d", a3, r3)
	}
	if len(keyset(t, be)) != 0 {
		t.Errorf("expected no managed rules after empty reconcile")
	}
}

// TestSanitize is the other hub-compromise guard: only one-IP rules on a valid
// port/proto with well-formed names survive, IPs come out canonical.
func TestSanitize(t *testing.T) {
	desired := []rule{
		{IP: "203.0.113.10", Port: 18080, Proto: "tcp", User: "alice", Group: "web"},
		{IP: "2001:DB8::1", Port: 18080, Proto: "tcp", User: "bob", Group: "web"},
		{IP: "any", Port: 18080, Proto: "tcp", User: "eve", Group: "web"},
		{IP: "0.0.0.0/0", Port: 18080, Proto: "tcp", User: "eve", Group: "web"},
		{IP: "203.0.113.11", Port: 0, Proto: "tcp", User: "eve", Group: "web"},
		{IP: "203.0.113.11", Port: 18080, Proto: "icmp", User: "eve", Group: "web"},
		{IP: "203.0.113.11", Port: 18080, Proto: "tcp", User: "eve:x", Group: "web"},
	}
	got := sanitize(desired)
	if len(got) != 2 || got[0].User != "alice" || got[1].IP != "2001:db8::1" {
		t.Fatalf("want alice + canonical bob only, got %+v", got)
	}
}

// TestFilterAllowed is the hub-compromise guard: with an allowlist set, only
// permitted ports survive; an empty allowlist passes everything (opt-in guard).
func TestFilterAllowed(t *testing.T) {
	desired := []rule{
		{IP: "1.1.1.1", Port: 18080, Proto: "tcp", User: "a", Group: "web"},
		{IP: "1.1.1.1", Port: 22, Proto: "tcp", User: "a", Group: "ssh"},
	}
	if got := filterAllowed(desired, nil); len(got) != 2 {
		t.Fatalf("nil allowlist must pass all, got %d", len(got))
	}
	got := filterAllowed(desired, []int{18080})
	if len(got) != 1 || got[0].Port != 18080 {
		t.Fatalf("allowlist [18080] must keep only 18080, got %+v", got)
	}
	if len(filterAllowed(desired, []int{443})) != 0 {
		t.Fatalf("allowlist [443] must drop both 18080 and 22")
	}
}

// hubStub answers the desired-state call with status and body.
func hubStub(t *testing.T, status int, body string) (string, *http.Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client()
}

// TestStepGuardFollowsHubPorts: the guard covers the hub's ports narrowed to
// agent_allowed_ports; nft_guard off removes it; a hub without "ports" (older
// than the agent) leaves it as it is.
func TestStepGuardFollowsHubPorts(t *testing.T) {
	ctx := context.Background()
	be := firewall.NewMockBackend("nft-okboy")
	body := `{"ok":true,"rules":[{"ip":"203.0.113.10","port":18080,"proto":"tcp","user":"alice","group":"web"}],
		"ports":[{"port":18080,"proto":"tcp"},{"port":22,"proto":"tcp"}]}`
	url, client := hubStub(t, 200, body)
	opts := Options{Guard: true, AllowedPorts: []int{18080}}

	step(ctx, be, client, url, opts, &state{})
	if len(be.Guarded) != 1 || be.Guarded[0] != (firewall.PortProto{Port: 18080, Proto: "tcp"}) {
		t.Fatalf("guard = %+v, want [18080/tcp] (22 is outside agent_allowed_ports)", be.Guarded)
	}
	if got := keyset(t, be); !got["203.0.113.10|tcp|alice|web"] {
		t.Fatalf("allow rule missing: %v", got)
	}

	opts.Guard = false
	step(ctx, be, client, url, opts, &state{})
	if be.Guarded != nil {
		t.Fatalf("nft_guard off must remove the guard, got %+v", be.Guarded)
	}

	be.Guarded = []firewall.PortProto{{Port: 9, Proto: "tcp"}}
	oldHub, oldClient := hubStub(t, 200, `{"ok":true,"rules":[]}`)
	step(ctx, be, oldClient, oldHub, Options{Guard: true}, &state{})
	if len(be.Guarded) != 1 || be.Guarded[0].Port != 9 {
		t.Fatalf("a hub without ports must leave the guard alone, got %+v", be.Guarded)
	}
}

// TestStepRevokedNodeFailsClosed: a 401 (node deleted on the hub) removes the
// allow rules but keeps the guard; any other failure keeps everything.
func TestStepRevokedNodeFailsClosed(t *testing.T) {
	ctx := context.Background()
	be := firewall.NewMockBackend("nft-okboy")
	_ = be.AddRule("203.0.113.10", 18080, "alice", "tcp", "web")
	be.Guarded = []firewall.PortProto{{Port: 18080, Proto: "tcp"}}

	url, client := hubStub(t, 502, "bad gateway")
	step(ctx, be, client, url, Options{Guard: true}, &state{})
	if len(keyset(t, be)) != 1 {
		t.Fatal("a hub outage must not touch the rules")
	}

	url, client = hubStub(t, 401, `{"ok":false,"error":"Invalid node token"}`)
	step(ctx, be, client, url, Options{Guard: true}, &state{})
	if len(keyset(t, be)) != 0 {
		t.Fatal("a rejected token must remove the allow rules")
	}
	if len(be.Guarded) != 1 {
		t.Fatalf("the guard must stay, got %+v", be.Guarded)
	}
}
