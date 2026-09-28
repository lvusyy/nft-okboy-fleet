package db

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSecretsAreOwnerOnly: the DB and its backups hold plaintext HMAC secrets
// and TOTP seeds, so they end up 0600 — even a DB file that already existed
// world-readable — and new directories 0700.
func TestSecretsAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := filepath.Join(t.TempDir(), "data")
	path := filepath.Join(dir, "t.db")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Init(); err != nil {
		t.Fatal(err)
	}
	d.Close()
	if err := os.Chmod(path, 0o644); err != nil { // e.g. created by an older version
		t.Fatal(err)
	}
	d, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	backup := filepath.Join(t.TempDir(), "bk", "b.db")
	if _, err := d.Backup(backup); err != nil {
		t.Fatal(err)
	}
	for f, want := range map[string]os.FileMode{dir: 0o700, path: 0o600, filepath.Dir(backup): 0o700, backup: 0o600} {
		st, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", f, got, want)
		}
	}
}

func tempDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := d.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// ConsumeTOTPCounter must advance only on a strictly-greater counter, so a
// replayed (or older) code is rejected atomically (the security primitive behind
// step-up replay protection).
func TestConsumeTOTPCounterRejectsReplay(t *testing.T) {
	d := tempDB(t)
	id, err := d.CreateUser("alice", "s", false)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.ConsumeTOTPCounter(id, 100); err != nil || !ok {
		t.Fatalf("first consume should advance: ok=%v err=%v", ok, err)
	}
	if ok, err := d.ConsumeTOTPCounter(id, 100); err != nil || ok {
		t.Fatalf("replay of counter 100 must be rejected: ok=%v err=%v", ok, err)
	}
	if ok, _ := d.ConsumeTOTPCounter(id, 99); ok {
		t.Fatal("older counter 99 must be rejected")
	}
	if ok, err := d.ConsumeTOTPCounter(id, 101); err != nil || !ok {
		t.Fatalf("newer counter 101 should advance: ok=%v err=%v", ok, err)
	}
}

// RecordIPChange must return the true prior IP and log an ip_change row ONLY when
// the IP actually changed (the atomic write that keeps stored IP, audit trail, and
// returned value consistent).
func TestRecordIPChangeAtomicAndHeartbeat(t *testing.T) {
	d := tempDB(t)
	id, err := d.CreateUser("bob", "s", false)
	if err != nil {
		t.Fatal(err)
	}
	count := func() int {
		var n int
		d.sql.QueryRow(`SELECT COUNT(*) FROM operation_log WHERE action='ip_change'`).Scan(&n)
		return n
	}

	prior, err := d.RecordIPChange(id, "bob", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if prior != nil {
		t.Fatalf("first knock prior should be nil, got %v", *prior)
	}
	if count() != 1 {
		t.Fatalf("first change should log 1 ip_change, got %d", count())
	}

	prior, _ = d.RecordIPChange(id, "bob", "2.2.2.2")
	if prior == nil || *prior != "1.1.1.1" {
		t.Fatalf("prior should be 1.1.1.1, got %v", prior)
	}
	if count() != 2 {
		t.Fatalf("second change should log 2 ip_change total, got %d", count())
	}

	before := count()
	prior, _ = d.RecordIPChange(id, "bob", "2.2.2.2") // heartbeat — same IP
	if prior == nil || *prior != "2.2.2.2" {
		t.Fatalf("heartbeat prior should be 2.2.2.2, got %v", prior)
	}
	if count() != before {
		t.Fatalf("heartbeat must not log an ip_change: before=%d after=%d", before, count())
	}
}

// The (port,proto) uniqueness index must reject a duplicate via a constraint error.
func TestGroupPortProtoUnique(t *testing.T) {
	d := tempDB(t)
	if _, err := d.CreateGroup("web", 8080, "tcp"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateGroup("web2", 8080, "tcp"); err == nil {
		t.Fatal("duplicate (8080,tcp) should violate the unique index")
	}
	// Different proto on the same port is allowed.
	if _, err := d.CreateGroup("web-udp", 8080, "udp"); err != nil {
		t.Fatalf("8080/udp should be allowed alongside 8080/tcp: %v", err)
	}
}
