// Package db is the SQLite persistence layer (pure-Go modernc.org/sqlite driver,
// so the final binary is static with no cgo). It mirrors the Python db.py schema,
// migrations, CRUD, logging, throttle counters, the atomic IP-change write, and
// the online backup — the single source of truth for users/groups/membership/logs.
package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a *sql.DB. The DSN sets foreign_keys, WAL, and busy_timeout on every
// pooled connection, mirroring the Python PRAGMAs.
type DB struct {
	sql  *sql.DB
	path string
}

type scanner interface{ Scan(...any) error }

// Open opens (creating parent dirs) the SQLite DB with the required PRAGMAs.
func Open(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	dsn := path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := sdb.Ping(); err != nil {
		return nil, err
	}
	return &DB{sql: sdb, path: path}, nil
}

// Conn exposes the underlying *sql.DB for the rare ad-hoc query (kept minimal).
func (d *DB) Conn() *sql.DB { return d.sql }
func (d *DB) Close() error  { return d.sql.Close() }
func (d *DB) Path() string  { return d.path }

// Init creates any missing tables, runs pending migrations, and ensures indexes.
func (d *DB) Init() error {
	for _, name := range schemaOrder {
		exists, err := d.tableExists(name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := d.sql.Exec(schemaDDL[name]); err != nil {
			return fmt.Errorf("create table %s: %w", name, err)
		}
	}
	if _, err := d.RunMigrations(); err != nil {
		return err
	}
	for _, ix := range indexDDL {
		if _, err := d.sql.Exec(ix); err != nil {
			return err
		}
	}
	return nil
}

// RunMigrations applies pending migrations in order, each in its own transaction.
func (d *DB) RunMigrations() ([]int, error) {
	cur, err := d.schemaVersion()
	if err != nil {
		return nil, err
	}
	var applied []int
	for _, m := range migrations {
		if m.Version <= cur {
			continue
		}
		tx, err := d.sql.Begin()
		if err != nil {
			return applied, err
		}
		if m.Apply != nil {
			if err := m.Apply(tx); err != nil {
				_ = tx.Rollback()
				return applied, fmt.Errorf("migration v%d: %w", m.Version, err)
			}
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO schema_version (version) VALUES (?)`, m.Version); err != nil {
			_ = tx.Rollback()
			return applied, err
		}
		if err := tx.Commit(); err != nil {
			return applied, err
		}
		applied = append(applied, m.Version)
	}
	return applied, nil
}

func (d *DB) schemaVersion() (int, error) {
	exists, err := d.tableExists("schema_version")
	if err != nil {
		return 0, err
	}
	if !exists {
		if _, err := d.sql.Exec(schemaDDL["schema_version"]); err != nil {
			return 0, err
		}
	}
	var v sql.NullInt64
	if err := d.sql.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&v); err != nil {
		return 0, err
	}
	if v.Valid {
		return int(v.Int64), nil
	}
	return 0, nil
}

func (d *DB) tableExists(name string) (bool, error) {
	var n string
	err := d.sql.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// ---- Users ---- //

const userCols = `id, username, secret, is_admin, current_ip, last_knock, totp_secret, totp_enabled, totp_last_counter, created_at`

func scanUser(s scanner) (*User, error) {
	var u User
	var isAdmin, totpEnabled int
	var curIP, totpSecret sql.NullString
	var lastKnock sql.NullInt64
	if err := s.Scan(&u.ID, &u.Username, &u.Secret, &isAdmin, &curIP, &lastKnock,
		&totpSecret, &totpEnabled, &u.TOTPLastCounter, &u.CreatedAt); err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin != 0
	u.TOTPEnabled = totpEnabled != 0
	if curIP.Valid {
		u.CurrentIP = &curIP.String
	}
	if totpSecret.Valid {
		u.TOTPSecret = &totpSecret.String
	}
	if lastKnock.Valid {
		lk := lastKnock.Int64
		u.LastKnock = &lk
	}
	return &u, nil
}

// CreateUser inserts a user and returns its id (errors on duplicate username).
func (d *DB) CreateUser(username, secret string, isAdmin bool) (int64, error) {
	res, err := d.sql.Exec(`INSERT INTO users (username, secret, is_admin) VALUES (?,?,?)`,
		username, secret, b2i(isAdmin))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetUserByUsername returns the user or (nil, nil) when not found.
func (d *DB) GetUserByUsername(username string) (*User, error) {
	u, err := scanUser(d.sql.QueryRow(`SELECT `+userCols+` FROM users WHERE username=?`, username))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// GetUser returns the user by id or (nil, nil) when not found.
func (d *DB) GetUser(id int64) (*User, error) {
	u, err := scanUser(d.sql.QueryRow(`SELECT `+userCols+` FROM users WHERE id=?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (d *DB) ListUsers() ([]User, error) {
	rows, err := d.sql.Query(`SELECT ` + userCols + ` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (d *DB) DeleteUser(id int64) error {
	_, err := d.sql.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

func (d *DB) SetUserAdmin(id int64, isAdmin bool) error {
	_, err := d.sql.Exec(`UPDATE users SET is_admin=? WHERE id=?`, b2i(isAdmin), id)
	return err
}

func (d *DB) RotateSecret(id int64, newSecret string) error {
	_, err := d.sql.Exec(`UPDATE users SET secret=? WHERE id=?`, newSecret, id)
	return err
}

func (d *DB) SetUserIP(id int64, ip string) error {
	_, err := d.sql.Exec(`UPDATE users SET current_ip=? WHERE id=?`, ip, id)
	return err
}

func (d *DB) ClearUserState(id int64) error {
	_, err := d.sql.Exec(`UPDATE users SET current_ip=NULL, last_knock=NULL WHERE id=?`, id)
	return err
}

func (d *DB) UpdateKnockTime(id int64, ip string) error {
	_, err := d.sql.Exec(`UPDATE users SET last_knock=?, current_ip=? WHERE id=?`, time.Now().Unix(), ip, id)
	return err
}

// GetUserIP returns the user's current registered IP (nil if none/unknown).
func (d *DB) GetUserIP(username string) (*string, error) {
	var ip sql.NullString
	err := d.sql.QueryRow(`SELECT current_ip FROM users WHERE username=?`, username).Scan(&ip)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if ip.Valid {
		return &ip.String, nil
	}
	return nil, nil
}

// RecordIPChange atomically claims ip for the user and returns the prior IP. It
// reads the prior current_ip and writes current_ip+last_knock (+ an ip_change
// op-log row ONLY when the IP changed) in ONE transaction, so the stored IP, the
// audit trail, and the returned value never disagree (the ORPHAN-D atomic write).
func (d *DB) RecordIPChange(userID int64, username, ip string) (*string, error) {
	tx, err := d.sql.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var prior sql.NullString
	if err := tx.QueryRow(`SELECT current_ip FROM users WHERE id=?`, userID).Scan(&prior); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE users SET current_ip=?, last_knock=? WHERE id=?`, ip, time.Now().Unix(), userID); err != nil {
		return nil, err
	}
	if !prior.Valid || prior.String != ip {
		old := "None"
		if prior.Valid {
			old = prior.String
		}
		if _, err := tx.Exec(`INSERT INTO operation_log (username, action, ip, detail) VALUES (?, 'ip_change', ?, ?)`,
			username, ip, "old="+old); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if prior.Valid {
		p := prior.String
		return &p, nil
	}
	return nil, nil
}

// ---- TOTP ---- //

func (d *DB) SetTOTPSecret(id int64, secret string) error {
	_, err := d.sql.Exec(`UPDATE users SET totp_secret=?, totp_enabled=0, totp_last_counter=0 WHERE id=?`, secret, id)
	return err
}

func (d *DB) EnableTOTP(id int64) error {
	_, err := d.sql.Exec(`UPDATE users SET totp_enabled=1 WHERE id=?`, id)
	return err
}

func (d *DB) DisableTOTP(id int64) error {
	_, err := d.sql.Exec(`UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE id=?`, id)
	return err
}

func (d *DB) SetTOTPLastCounter(id, counter int64) error {
	_, err := d.sql.Exec(`UPDATE users SET totp_last_counter=? WHERE id=?`, counter, id)
	return err
}

// ConsumeTOTPCounter atomically advances totp_last_counter to *counter*, but ONLY
// when the stored value is strictly less — rejecting replay of an already-consumed
// code in a single UPDATE (no check-then-set race two concurrent step-ups could
// win). Returns true if the counter advanced (i.e. the code was fresh).
func (d *DB) ConsumeTOTPCounter(id, counter int64) (bool, error) {
	res, err := d.sql.Exec(
		`UPDATE users SET totp_last_counter=? WHERE id=? AND totp_last_counter < ?`,
		counter, id, counter,
	)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ---- Groups ---- //

func scanGroup(s scanner) (*Group, error) {
	var g Group
	if err := s.Scan(&g.ID, &g.Name, &g.Port, &g.Proto, &g.CreatedAt); err != nil {
		return nil, err
	}
	return &g, nil
}

func (d *DB) CreateGroup(name string, port int, proto string) (int64, error) {
	res, err := d.sql.Exec(`INSERT INTO groups (name, port, proto) VALUES (?,?,?)`, name, port, proto)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) GetGroup(id int64) (*Group, error) {
	g, err := scanGroup(d.sql.QueryRow(`SELECT id,name,port,proto,created_at FROM groups WHERE id=?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return g, nil
}

func (d *DB) GetGroupByName(name string) (*Group, error) {
	g, err := scanGroup(d.sql.QueryRow(`SELECT id,name,port,proto,created_at FROM groups WHERE name=?`, name))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return g, nil
}

func (d *DB) GetGroupByPortProto(port int, proto string) (*Group, error) {
	g, err := scanGroup(d.sql.QueryRow(`SELECT id,name,port,proto,created_at FROM groups WHERE port=? AND proto=?`, port, proto))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return g, nil
}

func (d *DB) ListGroups() ([]Group, error) {
	rows, err := d.sql.Query(`SELECT id,name,port,proto,created_at FROM groups ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

func (d *DB) DeleteGroup(id int64) error {
	_, err := d.sql.Exec(`DELETE FROM groups WHERE id=?`, id)
	return err
}

// ---- Membership ---- //

func (d *DB) AddMembership(userID, groupID int64, enabled bool) error {
	_, err := d.sql.Exec(`INSERT INTO user_group_membership (user_id, group_id, enabled) VALUES (?,?,?)
		ON CONFLICT(user_id, group_id) DO UPDATE SET enabled=excluded.enabled`, userID, groupID, b2i(enabled))
	return err
}

func (d *DB) RemoveMembership(userID, groupID int64) error {
	_, err := d.sql.Exec(`DELETE FROM user_group_membership WHERE user_id=? AND group_id=?`, userID, groupID)
	return err
}

func (d *DB) SetMembershipEnabled(userID, groupID int64, enabled bool) error {
	_, err := d.sql.Exec(`UPDATE user_group_membership SET enabled=? WHERE user_id=? AND group_id=?`, b2i(enabled), userID, groupID)
	return err
}

// GetUserGroups returns the user's groups (only enabled when onlyEnabled).
func (d *DB) GetUserGroups(userID int64, onlyEnabled bool) ([]Group, error) {
	q := `SELECT g.id,g.name,g.port,g.proto,g.created_at FROM groups g
		JOIN user_group_membership m ON m.group_id=g.id WHERE m.user_id=?`
	if onlyEnabled {
		q += ` AND m.enabled=1`
	}
	q += ` ORDER BY g.id`
	rows, err := d.sql.Query(q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

// UserHasGroupAccess reports whether username may use/(re-)enable group_id. With
// allowReenable, any historical membership row passes (re-enable a previously
// authorized group); otherwise only a currently-enabled membership passes.
func (d *DB) UserHasGroupAccess(username string, groupID int64, allowReenable bool) (bool, error) {
	q := `SELECT 1 FROM user_group_membership m JOIN users u ON u.id=m.user_id WHERE u.username=? AND m.group_id=?`
	if !allowReenable {
		q += ` AND m.enabled=1`
	}
	var x int
	err := d.sql.QueryRow(q, username, groupID).Scan(&x)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetAllUserGroupPorts maps username -> enabled (group,port,proto) tuples, for
// stale-rule cleanup and UFW->DB sync recovery.
func (d *DB) GetAllUserGroupPorts() (map[string][]GroupPort, error) {
	rows, err := d.sql.Query(`SELECT u.username, g.name, g.port, g.proto
		FROM user_group_membership m
		JOIN users u ON u.id=m.user_id
		JOIN groups g ON g.id=m.group_id WHERE m.enabled=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]GroupPort{}
	for rows.Next() {
		var un, gn, proto string
		var port int
		if err := rows.Scan(&un, &gn, &port, &proto); err != nil {
			return nil, err
		}
		out[un] = append(out[un], GroupPort{Group: gn, Port: port, Proto: proto})
	}
	return out, rows.Err()
}

// UserGroupStates returns every group with this user's membership flags (admin panel).
func (d *DB) UserGroupStates(userID int64) ([]UserGroupState, error) {
	rows, err := d.sql.Query(`SELECT group_id, enabled FROM user_group_membership WHERE user_id=?`, userID)
	if err != nil {
		return nil, err
	}
	present := map[int64]bool{}
	enabled := map[int64]bool{}
	for rows.Next() {
		var gid int64
		var en int
		if err := rows.Scan(&gid, &en); err != nil {
			rows.Close()
			return nil, err
		}
		present[gid] = true
		enabled[gid] = en != 0
	}
	rows.Close()
	groups, err := d.ListGroups()
	if err != nil {
		return nil, err
	}
	out := make([]UserGroupState, 0, len(groups))
	for _, g := range groups {
		out = append(out, UserGroupState{
			ID: g.ID, Name: g.Name, Port: g.Port, Proto: g.Proto,
			IsMember: present[g.ID], Enabled: enabled[g.ID],
		})
	}
	return out, nil
}

// ---- Logs / throttle ---- //

func (d *DB) LogAudit(actor, action string, target, detail *string) error {
	_, err := d.sql.Exec(`INSERT INTO audit_log (actor, action, target, detail) VALUES (?,?,?,?)`,
		actor, action, target, detail)
	return err
}

func (d *DB) ListAudit(limit int) ([]AuditEntry, error) {
	rows, err := d.sql.Query(`SELECT id, actor, action, target, detail, created_at FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var target, detail sql.NullString
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &target, &detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		if target.Valid {
			e.Target = &target.String
		}
		if detail.Valid {
			e.Detail = &detail.String
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) RecordFailedAttempt(username, ip *string, reason string) error {
	_, err := d.sql.Exec(`INSERT INTO failed_attempts (username, ip, reason) VALUES (?,?,?)`, username, ip, reason)
	return err
}

func (d *DB) CountRecentFailedAttempts(ip string, windowSec int) (int, error) {
	var c int
	err := d.sql.QueryRow(`SELECT COUNT(*) FROM failed_attempts WHERE ip=? AND created_at >= datetime('now', ?)`,
		ip, fmt.Sprintf("-%d seconds", windowSec)).Scan(&c)
	return c, err
}

func (d *DB) CountRecentIPChanges(username string, windowSec int) (int, error) {
	var c int
	err := d.sql.QueryRow(`SELECT COUNT(*) FROM operation_log WHERE username=? AND action='ip_change' AND created_at >= datetime('now', ?)`,
		username, fmt.Sprintf("-%d seconds", windowSec)).Scan(&c)
	return c, err
}

func (d *DB) GetRecentIPChangeIPs(username string, windowSec int) ([]string, error) {
	rows, err := d.sql.Query(`SELECT ip FROM operation_log WHERE username=? AND action='ip_change' AND created_at >= datetime('now', ?)`,
		username, fmt.Sprintf("-%d seconds", windowSec))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip sql.NullString
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		if ip.Valid {
			out = append(out, ip.String)
		}
	}
	return out, rows.Err()
}

// ---- Backup ---- //

// Backup writes a consistent snapshot via VACUUM INTO (safe under WAL) and a
// sidecar .sha256 checksum, returning the hex digest.
func (d *DB) Backup(dest string) (string, error) {
	if dir := filepath.Dir(dest); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	if _, err := d.sql.Exec(`VACUUM INTO ?`, dest); err != nil {
		return "", err
	}
	f, err := os.Open(dest)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	_ = os.WriteFile(dest+".sha256", []byte(sum+"  "+filepath.Base(dest)+"\n"), 0o644)
	return sum, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
