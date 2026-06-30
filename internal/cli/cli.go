// Package cli holds the nft-okboy subcommand handlers — a faithful Go port of the
// cmd_* functions in the Python server/app.py. Each exported Cmd* function owns
// its own flag.FlagSet for sub-flags (--admin, --proto, --max-age, ...), parses
// the positional args, and performs the same DB + firewall side effects as its
// Python counterpart. The cmd/nft-okboy main only dispatches into these.
package cli

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"nft-okboy-fleet/internal/auth"
	"nft-okboy-fleet/internal/config"
	"nft-okboy-fleet/internal/db"
	"nft-okboy-fleet/internal/firewall"
	"nft-okboy-fleet/internal/server"
)

// totpIssuer labels otpauth:// URIs (matches the Python issuer string).
const totpIssuer = "nft-okboy"

// ====================================================================== //
//  Shared helpers
// ====================================================================== //

// genSecret returns a fresh 32-byte secret as lowercase hex — the exact analogue
// of Python's secrets.token_hex(32) (64 hex chars).
func genSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// openDB opens and initializes the database from config (Open + Init), mirroring
// the Python open_database() bootstrap minus the JSON seed (seeding is a
// server-bootstrap concern not exposed by the Go db layer).
func openDB(cfg *config.Config) (*db.DB, error) {
	d, err := db.Open(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open db %q: %w", cfg.DBPath, err)
	}
	if err := d.Init(); err != nil {
		d.Close()
		return nil, fmt.Errorf("init db: %w", err)
	}
	seedUsers(cfg, d)
	return d, nil
}

// seedUsers performs the one-time first-run seed of the config `users:` map into
// the DB (mirrors the Python open_database bootstrap): each configured user not
// already present is created with its config secret. Idempotent — existing users
// are untouched. Invalid names are skipped with a warning (SR-1).
func seedUsers(cfg *config.Config, d *db.DB) {
	for name, u := range cfg.Users {
		if u.Secret == "" {
			continue
		}
		if !firewall.ValidName(name) {
			log.Printf("seed: skipping invalid username %q", name)
			continue
		}
		existing, err := d.GetUserByUsername(name)
		if err != nil {
			log.Printf("seed: lookup %q failed: %v", name, err)
			continue
		}
		if existing != nil {
			continue
		}
		if _, err := d.CreateUser(name, u.Secret, false); err != nil {
			log.Printf("seed: create %q failed: %v", name, err)
		}
	}
}

// newManager builds the firewall policy Manager over the platform backend
// (nftables on Linux, mock elsewhere) — mirrors constructing the Python
// UFWManager for the management commands.
func newManager(cfg *config.Config, d *db.DB) (*firewall.Manager, error) {
	be, err := newBackend(cfg)
	if err != nil {
		return nil, err
	}
	return firewall.NewManager(be, d, cfg.RulePrefix), nil
}

// loadCfgDB is the common "load config + open db" preamble shared by most
// management commands. The caller is responsible for Close()ing the DB.
func loadCfgDB(cfgPath string) (*config.Config, *db.DB, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	d, err := openDB(cfg)
	if err != nil {
		return nil, nil, err
	}
	return cfg, d, nil
}

// audit writes one audit_log row, swallowing the (non-fatal) error after logging
// it — the CLI's best-effort trail, matching the Python db.log_audit("cli", ...)
// calls that never abort the command.
func audit(d *db.DB, action, target, detail string) {
	var tp, dp *string
	if target != "" {
		tp = &target
	}
	if detail != "" {
		dp = &detail
	}
	if err := d.LogAudit("cli", action, tp, dp); err != nil {
		log.Printf("audit log failed (%s): %v", action, err)
	}
}

// groupMembersWithIP returns every user with a recorded current IP who is a
// member of groupID. The Go db layer has no GetGroupMembers, so we reconstruct it
// from ListUsers + GetUserGroups (membership including disabled, since a disabled
// membership may still own an open firewall rule). Used by group deletion cleanup.
func groupMembersWithIP(d *db.DB, groupID int64) ([]db.User, error) {
	users, err := d.ListUsers()
	if err != nil {
		return nil, err
	}
	var out []db.User
	for i := range users {
		u := users[i]
		if u.CurrentIP == nil || *u.CurrentIP == "" {
			continue
		}
		groups, err := d.GetUserGroups(u.ID, false)
		if err != nil {
			return nil, err
		}
		for _, g := range groups {
			if g.ID == groupID {
				out = append(out, u)
				break
			}
		}
	}
	return out, nil
}

// strOr maps a *string to its value or a fallback for table rendering.
func strOr(p *string, fallback string) string {
	if p != nil && *p != "" {
		return *p
	}
	return fallback
}

// fmtKnock renders a unix last-knock timestamp like the Python "%Y-%m-%d %H:%M:%S",
// or "never" when unset.
func fmtKnock(ts *int64) string {
	if ts == nil {
		return "never"
	}
	return time.Unix(*ts, 0).Format("2006-01-02 15:04:05")
}

// ====================================================================== //
//  serve
// ====================================================================== //

// CmdServe loads config, opens the DB, builds the firewall Manager, ensures the
// base table/chain, and serves the HTTP API on listen_host:listen_port — the port
// of cmd_serve (here serving the real HTTP handler rather than Flask's dev
// server). EnsureBase failure is logged but non-fatal so a misconfigured firewall
// host can still expose /health for diagnosis.
func CmdServe(cfgPath, version string, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	debug := fs.Bool("debug", false, "Enable debug logging")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		log.Printf("debug logging enabled")
	} else {
		log.SetFlags(log.LstdFlags)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	d, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer d.Close()

	// Production serve REQUIRES a working firewall backend — a silent fall-back to
	// the mock would make /api/knock report success while opening NO real rule. On
	// Linux newBackend is the nftables backend (fail fast if nft is missing); on a
	// non-Linux dev build it is the mock by build tag, which is intentional.
	be, err := newBackend(cfg)
	if err != nil {
		return fmt.Errorf("firewall backend init failed (nftables required to serve): %w", err)
	}
	if err := be.EnsureBase(); err != nil {
		return fmt.Errorf("firewall EnsureBase failed (cannot manage nftables): %w", err)
	}
	fw := firewall.NewManager(be, d, cfg.RulePrefix)

	srv := server.NewServer(d, fw, cfg)
	srv.SetVersion(version)

	addr := fmt.Sprintf("%s:%d", cfg.ListenHost, cfg.ListenPort)
	httpSrv := &http.Server{Addr: addr, Handler: srv.Routes()}
	log.Printf("nft-okboy %s starting on %s", version, addr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// ====================================================================== //
//  gen-secret
// ====================================================================== //

// CmdGenSecret prints a fresh random secret (and a config snippet), porting
// cmd_gen_secret. The username positional is optional.
func CmdGenSecret(args []string) error {
	fs := flag.NewFlagSet("gen-secret", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	username := "<username>"
	if fs.NArg() >= 1 {
		username = fs.Arg(0)
	}
	secret, err := genSecret()
	if err != nil {
		return err
	}
	fmt.Printf("Generated secret for '%s':\n\n", username)
	fmt.Printf("  %s\n\n", secret)
	fmt.Printf("Add to config.yaml:\n\n")
	fmt.Printf("  users:\n")
	fmt.Printf("    %s:\n", username)
	fmt.Printf("      secret: \"%s\"\n", secret)
	fmt.Printf("\nClient config.yaml:\n\n")
	fmt.Printf("  username: \"%s\"\n", username)
	fmt.Printf("  secret: \"%s\"\n", secret)
	return nil
}

// ====================================================================== //
//  user-add / user-del / user-list
// ====================================================================== //

// CmdUserAdd creates a user with a random secret (ports cmd_user_add). --admin
// grants admin privileges. The generated secret is printed once.
func CmdUserAdd(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("user-add", flag.ContinueOnError)
	admin := fs.Bool("admin", false, "Grant admin privileges")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: user-add <username> [--admin]")
	}
	username := fs.Arg(0)
	if !firewall.ValidName(username) {
		return fmt.Errorf("invalid username %q (allowed: letters, digits, _ and -, max 64)", username)
	}

	_, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	secret, err := genSecret()
	if err != nil {
		return err
	}
	if _, err := d.CreateUser(username, secret, *admin); err != nil {
		return fmt.Errorf("create user %q: %w", username, err)
	}
	fmt.Printf("Created user '%s' with secret: %s\n", username, secret)
	audit(d, "user_add", username, fmt.Sprintf("is_admin=%t", *admin))
	return nil
}

// CmdUserDel deletes a user and cleans up their enabled-group firewall rules
// (ports cmd_user_del). A missing user is reported, not fatal.
func CmdUserDel(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("user-del", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: user-del <username>")
	}
	username := fs.Arg(0)

	cfg, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	user, err := d.GetUserByUsername(username)
	if err != nil {
		return err
	}
	if user == nil {
		fmt.Printf("User '%s' not found.\n", username)
		return nil
	}
	fw, err := newManager(cfg, d)
	if err != nil {
		return err
	}
	if user.CurrentIP != nil && *user.CurrentIP != "" {
		groups, err := d.GetUserGroups(user.ID, true)
		if err != nil {
			return err
		}
		for _, g := range groups {
			_ = fw.RemoveRule(*user.CurrentIP, g.Port, username, g.Proto, g.Name)
		}
	}
	if err := d.DeleteUser(user.ID); err != nil {
		return err
	}
	audit(d, "user_del", username, "")
	fmt.Printf("Deleted user '%s'.\n", username)
	return nil
}

// CmdUserList prints the user table (ports cmd_user_list): id, username, admin,
// current IP, last knock.
func CmdUserList(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("user-list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	users, err := d.ListUsers()
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Println("No users found.")
		return nil
	}
	fmt.Printf("%4s  %-20s  %-5s  %-16s  %s\n", "ID", "Username", "Admin", "Current IP", "Last Knock")
	for _, u := range users {
		admin := "No"
		if u.IsAdmin {
			admin = "Yes"
		}
		fmt.Printf("%4d  %-20s  %-5s  %-16s  %s\n",
			u.ID, u.Username, admin, strOr(u.CurrentIP, "(none)"), fmtKnock(u.LastKnock))
	}
	return nil
}

// ====================================================================== //
//  group-add / group-del / group-list
// ====================================================================== //

// CmdGroupAdd creates a port group (ports cmd_group_add) with validation: name
// charset (firewall.ValidName), port range 1..65535, and (port, proto)
// uniqueness via GetGroupByPortProto. --proto defaults to tcp.
func CmdGroupAdd(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("group-add", flag.ContinueOnError)
	proto := fs.String("proto", "tcp", "Protocol (default: tcp)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("usage: group-add <name> <port> [--proto tcp]")
	}
	name := fs.Arg(0)
	port, err := strconv.Atoi(fs.Arg(1))
	if err != nil {
		return fmt.Errorf("port must be an integer: %q", fs.Arg(1))
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of range (1-65535)", port)
	}
	if !firewall.ValidName(name) {
		return fmt.Errorf("invalid group name %q (allowed: alphanumeric start, then [A-Za-z0-9_-], max 64)", name)
	}

	_, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	dup, err := d.GetGroupByPortProto(port, *proto)
	if err != nil {
		return err
	}
	if dup != nil {
		fmt.Printf("Port %d/%s is already used by group '%s'.\n", port, *proto, dup.Name)
		return nil
	}
	if _, err := d.CreateGroup(name, port, *proto); err != nil {
		return fmt.Errorf("create group %q: %w", name, err)
	}
	fmt.Printf("Created group '%s' (port %d/%s)\n", name, port, *proto)
	audit(d, "group_add", name, fmt.Sprintf("port=%d proto=%s", port, *proto))
	return nil
}

// CmdGroupDel deletes a group and cleans up the firewall rules of its online
// members (ports cmd_group_del).
func CmdGroupDel(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("group-del", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: group-del <name>")
	}
	name := fs.Arg(0)

	cfg, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	group, err := d.GetGroupByName(name)
	if err != nil {
		return err
	}
	if group == nil {
		fmt.Printf("Group '%s' not found.\n", name)
		return nil
	}
	fw, err := newManager(cfg, d)
	if err != nil {
		return err
	}
	// The Go db layer exposes no GetGroupMembers, so derive the group's online
	// members from existing primitives: scan all users, and for each one with a
	// recorded IP, drop the rule if they belong to this group (any membership —
	// enabled or not — could still have an open rule). This reproduces the Python
	// cmd_group_del cleanup using only in-scope methods.
	members, err := groupMembersWithIP(d, group.ID)
	if err != nil {
		return err
	}
	for _, m := range members {
		_ = fw.RemoveRule(*m.CurrentIP, group.Port, m.Username, group.Proto, group.Name)
	}
	if err := d.DeleteGroup(group.ID); err != nil {
		return err
	}
	audit(d, "group_del", name, "")
	fmt.Printf("Deleted group '%s'.\n", name)
	return nil
}

// CmdGroupList prints the group table (ports cmd_group_list): id, name, port, proto.
func CmdGroupList(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("group-list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	groups, err := d.ListGroups()
	if err != nil {
		return err
	}
	if len(groups) == 0 {
		fmt.Println("No groups found.")
		return nil
	}
	fmt.Printf("%4s  %-20s  %5s  %s\n", "ID", "Name", "Port", "Proto")
	for _, g := range groups {
		fmt.Printf("%4d  %-20s  %5d  %s\n", g.ID, g.Name, g.Port, g.Proto)
	}
	return nil
}

// ====================================================================== //
//  user-join / user-leave
// ====================================================================== //

// CmdUserJoin adds a user to a group with an immediate UFW sync if the user is
// online (ports cmd_user_join). Membership is created enabled.
func CmdUserJoin(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("user-join", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("usage: user-join <username> <groupname>")
	}
	username, groupname := fs.Arg(0), fs.Arg(1)

	cfg, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	user, err := d.GetUserByUsername(username)
	if err != nil {
		return err
	}
	if user == nil {
		fmt.Printf("User '%s' not found.\n", username)
		return nil
	}
	group, err := d.GetGroupByName(groupname)
	if err != nil {
		return err
	}
	if group == nil {
		fmt.Printf("Group '%s' not found.\n", groupname)
		return nil
	}
	if err := d.AddMembership(user.ID, group.ID, true); err != nil {
		return err
	}
	if user.CurrentIP != nil && *user.CurrentIP != "" {
		fw, err := newManager(cfg, d)
		if err != nil {
			return err
		}
		_ = fw.AddRule(*user.CurrentIP, group.Port, username, group.Proto, group.Name)
	}
	audit(d, "user_join", username, groupname)
	fmt.Printf("Added '%s' to group '%s'.\n", username, groupname)
	return nil
}

// CmdUserLeave removes a user from a group and cleans up its firewall rule if the
// user is online (ports cmd_user_leave).
func CmdUserLeave(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("user-leave", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("usage: user-leave <username> <groupname>")
	}
	username, groupname := fs.Arg(0), fs.Arg(1)

	cfg, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	user, err := d.GetUserByUsername(username)
	if err != nil {
		return err
	}
	if user == nil {
		fmt.Printf("User '%s' not found.\n", username)
		return nil
	}
	group, err := d.GetGroupByName(groupname)
	if err != nil {
		return err
	}
	if group == nil {
		fmt.Printf("Group '%s' not found.\n", groupname)
		return nil
	}
	if user.CurrentIP != nil && *user.CurrentIP != "" {
		fw, err := newManager(cfg, d)
		if err != nil {
			return err
		}
		_ = fw.RemoveRule(*user.CurrentIP, group.Port, username, group.Proto, group.Name)
	}
	if err := d.RemoveMembership(user.ID, group.ID); err != nil {
		return err
	}
	audit(d, "user_leave", username, groupname)
	fmt.Printf("Removed '%s' from group '%s'.\n", username, groupname)
	return nil
}

// ====================================================================== //
//  admin-add
// ====================================================================== //

// CmdAdminAdd grants admin privileges to an existing user (ports cmd_admin_add).
func CmdAdminAdd(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("admin-add", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: admin-add <username>")
	}
	username := fs.Arg(0)

	_, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	user, err := d.GetUserByUsername(username)
	if err != nil {
		return err
	}
	if user == nil {
		fmt.Printf("User '%s' not found.\n", username)
		return nil
	}
	if err := d.SetUserAdmin(user.ID, true); err != nil {
		return err
	}
	audit(d, "admin_add", username, "")
	fmt.Printf("Granted admin privileges to '%s'.\n", username)
	return nil
}

// ====================================================================== //
//  revoke
// ====================================================================== //

// CmdRevoke force-disconnects a user: closes their enabled-group ports, clears
// runtime state, and (unless --no-rotate) rotates the HMAC secret, printing the
// new one once (ports cmd_revoke).
func CmdRevoke(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	noRotate := fs.Bool("no-rotate", false, "Disconnect without rotating the secret")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: revoke <username> [--no-rotate]")
	}
	username := fs.Arg(0)

	cfg, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	user, err := d.GetUserByUsername(username)
	if err != nil {
		return err
	}
	if user == nil {
		fmt.Printf("User '%s' not found.\n", username)
		return nil
	}
	if user.CurrentIP != nil && *user.CurrentIP != "" {
		fw, err := newManager(cfg, d)
		if err != nil {
			return err
		}
		groups, err := d.GetUserGroups(user.ID, true)
		if err != nil {
			return err
		}
		for _, g := range groups {
			_ = fw.RemoveRule(*user.CurrentIP, g.Port, username, g.Proto, g.Name)
		}
	}
	if err := d.ClearUserState(user.ID); err != nil {
		return err
	}
	var newSecret string
	if !*noRotate {
		newSecret, err = genSecret()
		if err != nil {
			return err
		}
		if err := d.RotateSecret(user.ID, newSecret); err != nil {
			return err
		}
	}
	audit(d, "revoke", username, fmt.Sprintf("rotate=%t", !*noRotate))
	fmt.Printf("Revoked '%s'. Ports closed, runtime state cleared.\n", username)
	if newSecret != "" {
		fmt.Printf("New secret (deliver to the user out-of-band): %s\n", newSecret)
	}
	return nil
}

// ====================================================================== //
//  list
// ====================================================================== //

// CmdList prints the managed firewall rules (ports the "=== UFW Rules (managed)
// ===" section of cmd_list) via fw.ListManaged().
func CmdList(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	fw, err := newManager(cfg, d)
	if err != nil {
		return err
	}
	rules, err := fw.ListManaged()
	if err != nil {
		return err
	}
	fmt.Println("=== Managed Firewall Rules ===")
	if len(rules) == 0 {
		fmt.Println("  (none)")
		return nil
	}
	for _, r := range rules {
		fmt.Printf("  %-16s -> %d/%s  [%s]\n", r.IP, r.Port, r.Proto, r.Comment)
	}
	return nil
}

// ====================================================================== //
//  cleanup
// ====================================================================== //

// CmdCleanup removes firewall rules for users idle beyond --max-age days (ports
// cmd_cleanup). The per-user enabled (group,port,proto) map drives precise
// removal across custom group ports, not just protected_ports.
func CmdCleanup(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	maxAge := fs.Int("max-age", 7, "Max age in days before a rule is considered stale (default: 7)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	fw, err := newManager(cfg, d)
	if err != nil {
		return err
	}
	ugp, err := d.GetAllUserGroupPorts()
	if err != nil {
		return err
	}
	removed, err := fw.CleanupStale(*maxAge*86400, ugp)
	if err != nil {
		return err
	}
	if len(removed) > 0 {
		fmt.Printf("Cleaned up %d stale user(s): %s\n", len(removed), joinComma(removed))
	} else {
		fmt.Println("No stale rules found.")
	}
	return nil
}

// ====================================================================== //
//  backup
// ====================================================================== //

// CmdBackup writes a timestamped, checksummed DB backup with rolling retention
// (ports cmd_backup). The two output lines below MUST stay exactly as written —
// the external upgrade script greps for "Backup written:".
func CmdBackup(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	dir := fs.String("dir", "", "Backup directory (default: config backup_dir)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	backupDir := *dir
	if backupDir == "" {
		backupDir = cfg.BackupDir
	}
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return fmt.Errorf("create backup dir %q: %w", backupDir, err)
	}
	stamp := time.Now().Format("20060102-150405.000000")
	dest := filepath.Join(backupDir, fmt.Sprintf("nft-okboy-%s.db", stamp))

	digest, err := d.Backup(dest) // also writes the .sha256 sidecar
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	// EXACT format — do not change (upgrade script greps "Backup written:").
	fmt.Printf("Backup written: %s\n", dest)
	fmt.Printf("  sha256: %s\n", digest)

	pruneBackups(backupDir, cfg.BackupKeep)
	return nil
}

// pruneBackups enforces rolling retention: keep the newest `keep` nft-okboy-*.db
// backups (and their .sha256 sidecars), removing the rest. keep <= 0 disables
// pruning, matching the Python guard.
func pruneBackups(dir string, keep int) {
	if keep <= 0 {
		return
	}
	matches, err := filepath.Glob(filepath.Join(dir, "nft-okboy-*.db"))
	if err != nil || len(matches) <= keep {
		return
	}
	sort.Strings(matches) // timestamped names sort chronologically
	for _, old := range matches[:len(matches)-keep] {
		if err := os.Remove(old); err == nil {
			_ = os.Remove(old + ".sha256")
			fmt.Printf("Pruned old backup: %s\n", filepath.Base(old))
		}
	}
}

// ====================================================================== //
//  totp-uri (convenience)
// ====================================================================== //

// CmdTOTPURI prints an otpauth:// enrollment URI for a user's current TOTP secret
// (convenience; no direct Python equivalent — uses auth.TOTPURI). Reports when
// the user is missing or has no secret enrolled.
func CmdTOTPURI(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("totp-uri", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: totp-uri <username>")
	}
	username := fs.Arg(0)

	_, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	user, err := d.GetUserByUsername(username)
	if err != nil {
		return err
	}
	if user == nil {
		fmt.Printf("User '%s' not found.\n", username)
		return nil
	}
	if user.TOTPSecret == nil || *user.TOTPSecret == "" {
		fmt.Printf("User '%s' has no TOTP secret enrolled.\n", username)
		return nil
	}
	fmt.Println(auth.TOTPURI(*user.TOTPSecret, username, totpIssuer))
	return nil
}

// joinComma joins a string slice with ", " (avoids importing strings for one use).
func joinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
