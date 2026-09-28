package cli

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"nft-okboy-fleet/internal/config"
	"nft-okboy-fleet/internal/db"
)

// TestParseFlagsAfterPositionals: flags work before or after positionals (the
// documented `user-add alice --admin` form), and "--" ends flag parsing.
func TestParseFlagsAfterPositionals(t *testing.T) {
	for _, c := range []struct {
		args  []string
		admin bool
		proto string
		pos   []string
	}{
		{[]string{"alice", "--admin"}, true, "tcp", []string{"alice"}},
		{[]string{"--admin", "alice"}, true, "tcp", []string{"alice"}},
		{[]string{"web", "8080", "--proto", "udp"}, false, "udp", []string{"web", "8080"}},
		{[]string{"web", "--proto=udp", "8080"}, false, "udp", []string{"web", "8080"}},
		{[]string{"--", "alice", "--admin"}, false, "tcp", []string{"alice", "--admin"}},
		{nil, false, "tcp", []string{}},
	} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		admin := fs.Bool("admin", false, "")
		proto := fs.String("proto", "tcp", "")
		if err := parseFlags(fs, c.args); err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		if *admin != c.admin || *proto != c.proto || !reflect.DeepEqual(append([]string{}, fs.Args()...), c.pos) {
			t.Errorf("%v: admin=%v proto=%q args=%q; want %v %q %q", c.args, *admin, *proto, fs.Args(), c.admin, c.proto, c.pos)
		}
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	if err := parseFlags(fs, []string{"alice", "--nope"}); err == nil {
		t.Error("an unknown flag after a positional must be an error")
	}
}

// TestCheckHubURL: https anywhere; plain http only on loopback or with --allow-http.
func TestCheckHubURL(t *testing.T) {
	for _, ok := range []string{"https://hub.example/", "https://203.0.113.1:8443", "http://127.0.0.1:5000", "http://localhost:5000/", "http://[::1]:5000"} {
		if err := checkHubURL(ok, false); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://hub.example/", "http://203.0.113.1:5000", "ftp://hub.example", "hub.example", ""} {
		if err := checkHubURL(bad, false); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := checkHubURL("http://nft-okboy-hub:5000", true); err != nil {
		t.Errorf("--allow-http must accept an in-cluster http hub: %v", err)
	}
	if err := checkHubURL("ftp://hub.example", true); err == nil {
		t.Error("--allow-http must not accept other schemes")
	}
}

// TestSeedUsersFreshDBOnly: the config seed runs on a freshly created DB only (a deleted
// user must not come back with its old secret), and skips placeholder secrets.
func TestSeedUsersFreshDBOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	d, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { d.Close() }()
	if err := d.Init(); err != nil {
		t.Fatal(err)
	}
	long := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg := &config.Config{Users: map[string]config.UserSeed{
		"alice": {Secret: long},
		"admin": {Secret: "<64 hex chars>"},
	}}
	seedUsers(cfg, d)
	if u, _ := d.GetUserByUsername("alice"); u == nil {
		t.Fatal("alice must be seeded on a fresh DB")
	}
	if u, _ := d.GetUserByUsername("admin"); u != nil {
		t.Fatal("a placeholder secret must not be seeded")
	}
	u, _ := d.GetUserByUsername("alice")
	if err := d.DeleteUser(u.ID); err != nil { // no users left at all
		t.Fatal(err)
	}
	d.Close()
	d, err = db.Open(path) // the next start
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Init(); err != nil {
		t.Fatal(err)
	}
	seedUsers(cfg, d)
	if u, _ := d.GetUserByUsername("alice"); u != nil {
		t.Fatal("a deleted user must not be re-seeded, even into an empty users table")
	}
}

// TestPruneBackupsTightensAll: backups within the retention count, or with
// retention off, are made owner-only too — older versions wrote them
// world-readable, with the same plaintext secrets as the database.
func TestPruneBackupsTightensAll(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	for _, keep := range []int{7, 0} {
		dir := t.TempDir()
		f := filepath.Join(dir, "nft-okboy-20260101-000000.db")
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		pruneBackups(dir, keep)
		st, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("keep=%d: backup mode %v, want 0600", keep, st.Mode().Perm())
		}
	}
}
