package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"
)

// HashToken returns the hex sha256 of a node enrollment token. Only the hash is
// stored; the raw token is shown once at node creation and presented by the agent
// as a bearer credential.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

const nodeCols = `id, name, token_hash, last_seen, agent_version, agent_backend, created_at`

func scanNode(s scanner) (*Node, error) {
	var n Node
	var lastSeen sql.NullInt64
	var ver, backend sql.NullString
	if err := s.Scan(&n.ID, &n.Name, &n.TokenHash, &lastSeen, &ver, &backend, &n.CreatedAt); err != nil {
		return nil, err
	}
	if lastSeen.Valid {
		ls := lastSeen.Int64
		n.LastSeen = &ls
	}
	if ver.Valid {
		n.AgentVersion = &ver.String
	}
	if backend.Valid {
		n.AgentBackend = &backend.String
	}
	return &n, nil
}

// CreateNode registers an edge node with its name and token hash, returning its id.
func (d *DB) CreateNode(name, tokenHash string) (int64, error) {
	res, err := d.sql.Exec(`INSERT INTO nodes (name, token_hash) VALUES (?,?)`, name, tokenHash)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) GetNodeByName(name string) (*Node, error) {
	n, err := scanNode(d.sql.QueryRow(`SELECT `+nodeCols+` FROM nodes WHERE name=?`, name))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return n, nil
}

// GetNodeByTokenHash returns the node whose token hash matches, or (nil, nil) —
// the agent-auth lookup. The caller hashes the presented bearer token first.
func (d *DB) GetNodeByTokenHash(hash string) (*Node, error) {
	n, err := scanNode(d.sql.QueryRow(`SELECT `+nodeCols+` FROM nodes WHERE token_hash=?`, hash))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return n, nil
}

func (d *DB) ListNodes() ([]Node, error) {
	rows, err := d.sql.Query(`SELECT ` + nodeCols + ` FROM nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

func (d *DB) DeleteNode(id int64) error {
	_, err := d.sql.Exec(`DELETE FROM nodes WHERE id=?`, id)
	return err
}

// TouchNode records that the node's agent just contacted the hub (last_seen=now).
func (d *DB) TouchNode(id int64) error {
	_, err := d.sql.Exec(`UPDATE nodes SET last_seen=? WHERE id=?`, time.Now().Unix(), id)
	return err
}

// UpdateNodeReport records the agent's contact: last_seen=now plus its reported
// version and firewall backend (the fleet dashboard's liveness + upgrade view).
// Empty values are stored as NULL so "never reported" stays distinguishable.
func (d *DB) UpdateNodeReport(id int64, version, backend string) error {
	_, err := d.sql.Exec(`UPDATE nodes SET last_seen=?, agent_version=?, agent_backend=? WHERE id=?`,
		time.Now().Unix(), nullStr(version), nullStr(backend), id)
	return err
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// AddGroupTarget upserts a (group, node) target's port/proto. A second call for
// the same (group, node) updates the port/proto in place (UNIQUE constraint).
func (d *DB) AddGroupTarget(groupID, nodeID int64, port int, proto string) error {
	_, err := d.sql.Exec(`INSERT INTO group_targets (group_id, node_id, port, proto) VALUES (?,?,?,?)
		ON CONFLICT(group_id, node_id) DO UPDATE SET port=excluded.port, proto=excluded.proto`,
		groupID, nodeID, port, proto)
	return err
}

func (d *DB) RemoveGroupTarget(groupID, nodeID int64) error {
	_, err := d.sql.Exec(`DELETE FROM group_targets WHERE group_id=? AND node_id=?`, groupID, nodeID)
	return err
}

// ListGroupTargets returns every target joined with its group + node names.
func (d *DB) ListGroupTargets() ([]GroupTargetView, error) {
	rows, err := d.sql.Query(`SELECT g.name, n.name, gt.port, gt.proto
		FROM group_targets gt
		JOIN groups g ON g.id = gt.group_id
		JOIN nodes  n ON n.id = gt.node_id
		ORDER BY n.name, g.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupTargetView
	for rows.Next() {
		var v GroupTargetView
		if err := rows.Scan(&v.Group, &v.Node, &v.Port, &v.Proto); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// DesiredStateForNode computes the allow rules an agent on nodeID must enforce:
// for every user with a recorded IP and an ENABLED membership in a group that
// targets this node, one rule (user.current_ip, target.port, target.proto) for
// (user, group). It is the per-node projection the agent reconciles against —
// a knock that updates a user's current_ip automatically changes what every
// node the user is authorized on will serve on the next pull (implicit fan-out).
func (d *DB) DesiredStateForNode(nodeID int64) ([]DesiredRule, error) {
	rows, err := d.sql.Query(`SELECT u.current_ip, gt.port, gt.proto, u.username, g.name
		FROM group_targets gt
		JOIN groups g ON g.id = gt.group_id
		JOIN user_group_membership m ON m.group_id = gt.group_id AND m.enabled = 1
		JOIN users u ON u.id = m.user_id
		WHERE gt.node_id = ? AND u.current_ip IS NOT NULL AND u.current_ip != ''`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DesiredRule
	for rows.Next() {
		var r DesiredRule
		if err := rows.Scan(&r.IP, &r.Port, &r.Proto, &r.User, &r.Group); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
