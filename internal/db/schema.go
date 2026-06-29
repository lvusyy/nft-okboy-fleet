package db

import "database/sql"

// schemaDDL mirrors db.py:SCHEMA exactly. The v2-v4 columns are inline in the
// users baseline (so fresh installs get them directly); the migration funcs only
// matter for in-place upgrades of an older DB. modernc.org/sqlite speaks the same
// SQL, so the DDL transfers unchanged.
var schemaDDL = map[string]string{
	"schema_version": `CREATE TABLE schema_version (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (datetime('now')))`,
	"users": `CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		secret TEXT NOT NULL,
		is_admin INTEGER NOT NULL DEFAULT 0,
		current_ip TEXT,
		last_knock INTEGER,
		totp_secret TEXT,
		totp_enabled INTEGER NOT NULL DEFAULT 0,
		totp_last_counter INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
	"groups": `CREATE TABLE groups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		port INTEGER NOT NULL,
		proto TEXT NOT NULL DEFAULT 'tcp',
		created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
	"user_group_membership": `CREATE TABLE user_group_membership (
		user_id INTEGER NOT NULL,
		group_id INTEGER NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		joined_at TEXT NOT NULL DEFAULT (datetime('now')),
		PRIMARY KEY (user_id, group_id),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE)`,
	"audit_log": `CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		actor TEXT NOT NULL,
		action TEXT NOT NULL,
		target TEXT,
		detail TEXT,
		created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
	"operation_log": `CREATE TABLE operation_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		action TEXT NOT NULL,
		ip TEXT,
		detail TEXT,
		created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
	"failed_attempts": `CREATE TABLE failed_attempts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT,
		ip TEXT,
		reason TEXT,
		created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
	"nodes": `CREATE TABLE nodes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		token_hash TEXT UNIQUE NOT NULL,
		last_seen INTEGER,
		agent_version TEXT,
		agent_backend TEXT,
		created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
	"group_targets": `CREATE TABLE group_targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		group_id INTEGER NOT NULL,
		node_id INTEGER NOT NULL,
		port INTEGER NOT NULL,
		proto TEXT NOT NULL DEFAULT 'tcp',
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		UNIQUE (group_id, node_id),
		FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
		FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE)`,
}

// schemaOrder creates tables in FK-safe order (users/groups before membership).
var schemaOrder = []string{
	"schema_version", "users", "groups",
	"user_group_membership", "audit_log", "operation_log", "failed_attempts",
	"nodes", "group_targets",
}

// indexDDL mirrors db.py:_create_indexes — the hot-path indexes.
var indexDDL = []string{
	`CREATE INDEX IF NOT EXISTS idx_oplog_user_action_time ON operation_log(username, action, created_at)`,
	`CREATE INDEX IF NOT EXISTS idx_failed_attempts_username ON failed_attempts(username, created_at)`,
	`CREATE INDEX IF NOT EXISTS idx_failed_attempts_ip ON failed_attempts(ip, created_at)`,
	`CREATE INDEX IF NOT EXISTS idx_group_targets_node ON group_targets(node_id)`,
}

// migration mirrors an entry of db.py:MIGRATIONS. Apply is nil for v1 (the
// record-only baseline); v2-v4 are idempotent ALTERs guarded by column checks.
type migration struct {
	Version int
	Desc    string
	Apply   func(*sql.Tx) error
}

var migrations = []migration{
	{1, "baseline 6-table schema + legacy seed", nil},
	{2, "add TOTP step-up columns (totp_secret, totp_enabled)", migrate002TOTP},
	{3, "add totp_last_counter (TOTP replay protection)", migrate003TOTPCounter},
	{4, "add UNIQUE(port, proto) index on groups when data permits", migrate004GroupsUnique},
	{5, "add nodes + group_targets tables (C2 hub: per-node desired state)", nil},
	{6, "add agent_version + agent_backend to nodes (fleet dashboard)", migrate006NodeReport},
}

// CurrentSchemaVersion is the highest migration version (mirrors db.py).
var CurrentSchemaVersion = migrations[len(migrations)-1].Version

func migrate002TOTP(tx *sql.Tx) error {
	if ok, err := colExists(tx, "users", "totp_secret"); err != nil {
		return err
	} else if !ok {
		if _, err := tx.Exec(`ALTER TABLE users ADD COLUMN totp_secret TEXT`); err != nil {
			return err
		}
	}
	if ok, err := colExists(tx, "users", "totp_enabled"); err != nil {
		return err
	} else if !ok {
		if _, err := tx.Exec(`ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	return nil
}

func migrate003TOTPCounter(tx *sql.Tx) error {
	if ok, err := colExists(tx, "users", "totp_last_counter"); err != nil {
		return err
	} else if !ok {
		if _, err := tx.Exec(`ALTER TABLE users ADD COLUMN totp_last_counter INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	return nil
}

// migrate004GroupsUnique adds UNIQUE(port, proto) DEFENSIVELY: a legacy groups
// table without those columns, or one already holding duplicate (port,proto)
// rows, is left untouched (logged-skip) so the migration never crashes or drops
// data. Such installs keep relying on the app-level 409 check.
func migrate004GroupsUnique(tx *sql.Tx) error {
	hasPort, err := colExists(tx, "groups", "port")
	if err != nil {
		return err
	}
	hasProto, err := colExists(tx, "groups", "proto")
	if err != nil {
		return err
	}
	if !hasPort || !hasProto {
		return nil
	}
	var dups int
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM (SELECT port, proto FROM groups GROUP BY port, proto HAVING COUNT(*) > 1)`,
	).Scan(&dups); err != nil {
		return err
	}
	if dups > 0 {
		return nil // duplicates present — skip the unique index, keep data
	}
	_, err = tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_port_proto ON groups(port, proto)`)
	return err
}

// migrate006NodeReport adds the agent self-report columns to an existing nodes
// table (fresh installs get them from the baseline DDL). Idempotent via colExists.
func migrate006NodeReport(tx *sql.Tx) error {
	for _, col := range []string{"agent_version", "agent_backend"} {
		ok, err := colExists(tx, "nodes", col)
		if err != nil {
			return err
		}
		if !ok {
			if _, err := tx.Exec("ALTER TABLE nodes ADD COLUMN " + col + " TEXT"); err != nil {
				return err
			}
		}
	}
	return nil
}

// colExists reports whether table has a column named col. The table name is a
// compile-time constant from this file (never user input), so the unavoidable
// string interpolation into PRAGMA is safe.
func colExists(tx *sql.Tx, table, col string) (bool, error) {
	rows, err := tx.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == col {
			return true, nil
		}
	}
	return false, rows.Err()
}
