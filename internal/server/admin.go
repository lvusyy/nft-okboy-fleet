package server

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"

	"nft-okboy-fleet/internal/auth"
	"nft-okboy-fleet/internal/db"
	"nft-okboy-fleet/internal/firewall"
)

// adminError writes the admin auth-failure envelope, mirroring app.py's
// _admin_error_response: 403 for "Admin privileges required", 401 otherwise
// (unknown user / bad signature / expired). Body is {"ok":false,"error":err}.
func (s *Server) adminError(w http.ResponseWriter, err string) {
	status := http.StatusUnauthorized
	if err == "Admin privileges required" {
		status = http.StatusForbidden
	}
	errJSON(w, status, err)
}

// requireAdmin runs the admin HMAC check; on failure it writes the proper
// 401/403 envelope and returns (nil, false). Thin shared head of every admin
// handler (the Go form of `user, err = auth.require_admin(...); if err: ...`).
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (*db.User, bool) {
	user, err := auth.RequireAdmin(s.db, r.Header.Get("Authorization"), s.cfg.SignatureTTL, s.clientIP(r))
	if err != "" {
		s.adminError(w, err)
		return nil, false
	}
	return user, true
}

// genSecret returns a 32-byte random hex secret (64 hex chars), the exact Go
// analogue of Python secrets.token_hex(32).
func genSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never short-reads without an error; a failure means the OS
		// CSPRNG is unavailable, which is unrecoverable.
		panic("server: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// ---- Users ---- //

// adminListUsers lists all users (admin only); secret AND totp_secret are stripped
// from each row before serialization (the TOTP seed is never exposed). Mirrors
// app.py admin_list_users(): the user dict minus those two keys.
func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	rows, err := s.db.ListUsers()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	users := make([]map[string]any, 0, len(rows))
	for _, u := range rows {
		users = append(users, userPublic(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "users": users})
}

// userPublic projects a User to the admin-list JSON shape, omitting secret and
// totp_secret. Field names match the Python sqlite row keys the web client reads.
func userPublic(u db.User) map[string]any {
	var curIP any = nil
	if u.CurrentIP != nil {
		curIP = *u.CurrentIP
	}
	var lastKnock any = nil
	if u.LastKnock != nil {
		lastKnock = *u.LastKnock
	}
	return map[string]any{
		"id":                u.ID,
		"username":          u.Username,
		"is_admin":          b2iJSON(u.IsAdmin),
		"current_ip":        curIP,
		"last_knock":        lastKnock,
		"totp_enabled":      b2iJSON(u.TOTPEnabled),
		"totp_last_counter": u.TOTPLastCounter,
		"created_at":        u.CreatedAt,
	}
}

// adminCreateUser creates a user (admin + step-up). The secret is the client-
// supplied one or a fresh token_hex(32); a duplicate username is 409. Returns 201
// with the secret echoed once. Mirrors app.py admin_create_user().
func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	body := readJSON(r)
	if s.stepUp(w, r, user, body) {
		return
	}
	username := jsonString(body, "username")
	if username == "" {
		errJSON(w, http.StatusBadRequest, "username is required")
		return
	}
	if !firewall.ValidName(username) {
		errJSON(w, http.StatusBadRequest, "Invalid username (allowed: letters, digits, _ and -, max 64)")
		return
	}
	secret := jsonString(body, "secret")
	if secret == "" {
		secret = genSecret()
	}
	isAdmin := jsonBoolDefault(body, "is_admin", false)
	id, err := s.db.CreateUser(username, secret, isAdmin)
	if err != nil {
		// A UNIQUE(username) violation is the expected duplicate path (409); any
		// other error is a 500.
		if isUniqueViolation(err) {
			errJSON(w, http.StatusConflict, "User '"+username+"' already exists")
			return
		}
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	_ = s.db.LogAudit(user.Username, "user_add", strPtr(username), strPtr("is_admin="+boolPy(isAdmin)))
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok": true, "id": id, "username": username, "secret": secret, "is_admin": isAdmin,
	})
}

// adminDeleteUser deletes a user and cleans up their UFW rules first (admin +
// step-up). Mirrors app.py admin_delete_user(): 404 if missing, remove each
// enabled-group rule for the user's current IP, then delete + audit.
func (s *Server) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	body := readJSON(r)
	if s.stepUp(w, r, user, body) {
		return
	}
	userID, okID := pathInt(r, "user_id")
	if !okID {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}
	target, err := s.db.GetUser(userID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if target == nil {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}
	if target.CurrentIP != nil && *target.CurrentIP != "" {
		groups, _ := s.db.GetUserGroups(userID, true)
		for _, g := range groups {
			_ = s.fw.RemoveRule(*target.CurrentIP, g.Port, target.Username, g.Proto, g.Name)
		}
	}
	if err := s.db.DeleteUser(userID); err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	_ = s.db.LogAudit(user.Username, "user_del", strPtr(target.Username), nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": userID})
}

// adminSetAdmin promotes/demotes a user's admin flag (admin + step-up). Mirrors
// app.py admin_set_admin(): is_admin defaults to true when absent.
func (s *Server) adminSetAdmin(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	body := readJSON(r)
	if s.stepUp(w, r, user, body) {
		return
	}
	userID, okID := pathInt(r, "user_id")
	if !okID {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}
	target, err := s.db.GetUser(userID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if target == nil {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}
	isAdmin := jsonBoolDefault(body, "is_admin", true)
	if err := s.db.SetUserAdmin(userID, isAdmin); err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	_ = s.db.LogAudit(user.Username, "set_admin", strPtr(target.Username), strPtr("is_admin="+boolPy(isAdmin)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user_id": userID, "is_admin": isAdmin})
}

// adminUserGroups lists every group with the target user's membership flags
// (admin only). Mirrors app.py admin_user_groups(): db.UserGroupStates powers the
// admin console's per-user checkbox panel. UserGroupState carries JSON tags
// {id,name,port,proto,is_member,enabled}, so it serializes directly.
func (s *Server) adminUserGroups(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	userID, okID := pathInt(r, "user_id")
	if !okID {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}
	target, err := s.db.GetUser(userID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if target == nil {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}
	states, err := s.db.UserGroupStates(userID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user_id": userID, "groups": states})
}

// adminAddMembership adds a user to a group (admin + step-up). Mirrors app.py
// admin_add_membership(): 404 on missing user/group, enabled defaults to true,
// and on an immediate online sync (target has a current IP AND enabled) the port
// is opened now. Returns 201.
func (s *Server) adminAddMembership(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	body := readJSON(r)
	if s.stepUp(w, r, user, body) {
		return
	}
	userID, okID := pathInt(r, "user_id")
	if !okID {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}
	target, err := s.db.GetUser(userID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if target == nil {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}
	groupID, okG := jsonInt(body, "group_id")
	if !okG {
		errJSON(w, http.StatusBadRequest, "group_id is required")
		return
	}
	group, err := s.db.GetGroup(int64(groupID))
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if group == nil {
		errJSON(w, http.StatusNotFound, "Group not found")
		return
	}
	enabled := jsonBoolDefault(body, "enabled", true)
	if err := s.db.AddMembership(userID, int64(groupID), enabled); err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if target.CurrentIP != nil && *target.CurrentIP != "" && enabled {
		_ = s.fw.AddRule(*target.CurrentIP, group.Port, target.Username, group.Proto, group.Name)
	}
	_ = s.db.LogAudit(user.Username, "user_join", strPtr(target.Username), strPtr(group.Name))
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok": true, "user_id": userID, "group_id": groupID, "enabled": b2iJSON(enabled),
	})
}

// adminRemoveMembership removes a user from a group and cleans up the UFW rule
// (admin + step-up). Body is {username, group_name}. Mirrors app.py
// admin_remove_membership(): 404 on missing user/group, remove the rule if the
// user is online, then drop the membership + audit.
func (s *Server) adminRemoveMembership(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	body := readJSON(r)
	if s.stepUp(w, r, user, body) {
		return
	}
	target, err := s.db.GetUserByUsername(jsonString(body, "username"))
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	group, gerr := s.db.GetGroupByName(jsonString(body, "group_name"))
	if gerr != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if target == nil {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}
	if group == nil {
		errJSON(w, http.StatusNotFound, "Group not found")
		return
	}
	if err := s.db.RemoveMembership(target.ID, group.ID); err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if target.CurrentIP != nil && *target.CurrentIP != "" {
		_ = s.fw.RemoveRule(*target.CurrentIP, group.Port, target.Username, group.Proto, group.Name)
	}
	_ = s.db.LogAudit(user.Username, "remove_membership", strPtr(target.Username), strPtr(group.Name))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "user_id": target.ID, "group_id": group.ID,
	})
}

// adminRevokeUser revokes a user's active access (admin + step-up): close their
// open ports, clear runtime state, and (by default) rotate the HMAC secret so the
// old credential is invalid immediately. {"rotate_secret":false} disconnects
// without rotating. The new secret is returned ONCE. Mirrors app.py
// admin_revoke_user().
func (s *Server) adminRevokeUser(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	body := readJSON(r)
	if s.stepUp(w, r, user, body) {
		return
	}
	userID, okID := pathInt(r, "user_id")
	if !okID {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}
	target, err := s.db.GetUser(userID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if target == nil {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}
	// Remove the user's open rules. revoke is a security op with NO self-heal (a
	// cleared/rotated user won't knock again to trigger reconcile), so a removal
	// failure leaves the old IP allowed until the cleanup timer — surface it.
	var fwFailed []string
	if target.CurrentIP != nil && *target.CurrentIP != "" {
		groups, _ := s.db.GetUserGroups(userID, true)
		for _, g := range groups {
			if e := s.fw.RemoveRule(*target.CurrentIP, g.Port, target.Username, g.Proto, g.Name); e != nil {
				fwFailed = append(fwFailed, g.Name)
			}
		}
	}
	if err := s.db.ClearUserState(userID); err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	rotate := jsonBoolDefault(body, "rotate_secret", true)
	var newSecret string
	if rotate {
		newSecret = genSecret()
		if err := s.db.RotateSecret(userID, newSecret); err != nil {
			errJSON(w, http.StatusInternalServerError, "Internal error")
			return
		}
	}
	_ = s.db.LogAudit(user.Username, "revoke", strPtr(target.Username), strPtr("rotate="+boolPy(rotate)))
	resp := map[string]any{"ok": true, "user_id": userID, "rotated": rotate}
	if newSecret != "" {
		resp["secret"] = newSecret
	}
	if len(fwFailed) > 0 {
		resp["warning"] = "firewall rule removal failed for groups: " + strings.Join(fwFailed, ", ") +
			" — run 'nft-okboy cleanup' or check nftables"
		_ = s.db.LogAudit(user.Username, "revoke_fw_error", strPtr(target.Username), strPtr(strings.Join(fwFailed, ",")))
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- Groups ---- //

// adminListGroups lists all groups (admin only). Mirrors app.py admin_list_groups().
func (s *Server) adminListGroups(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	groups, err := s.db.ListGroups()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	out := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		out = append(out, map[string]any{
			"id": g.ID, "name": g.Name, "port": g.Port, "proto": g.Proto, "created_at": g.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "groups": out})
}

// adminCreateGroup creates a group (admin + step-up). Mirrors app.py
// admin_create_group() exactly:
//   - name and port required (400);
//   - port must parse as int (400 "port must be an integer");
//   - if cfg.AllowedPorts is non-empty, the port must be in it (400 + audit);
//   - (port, proto) uniqueness via GetGroupByPortProto → 409;
//   - name charset validated with firewall.ValidName;
//   - on a UNIQUE race at insert, name the real cause (409).
func (s *Server) adminCreateGroup(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	body := readJSON(r)
	if s.stepUp(w, r, user, body) {
		return
	}
	name := jsonString(body, "name")
	_, portPresent := body["port"]
	if name == "" || !portPresent || body["port"] == nil {
		errJSON(w, http.StatusBadRequest, "name and port are required")
		return
	}
	proto := jsonString(body, "proto")
	if proto == "" {
		proto = "tcp"
	}
	portInt, okPort := jsonInt(body, "port")
	if !okPort {
		errJSON(w, http.StatusBadRequest, "port must be an integer")
		return
	}
	if portInt < 1 || portInt > 65535 {
		errJSON(w, http.StatusBadRequest, "port out of range (1-65535)")
		return
	}
	if proto != "tcp" && proto != "udp" {
		errJSON(w, http.StatusBadRequest, "proto must be tcp or udp")
		return
	}

	// allowed_ports whitelist (VULN-B): only enforced when configured.
	if len(s.cfg.AllowedPorts) > 0 && !containsInt(s.cfg.AllowedPorts, portInt) {
		_ = s.db.LogAudit(user.Username, "group_add_denied", strPtr(name),
			strPtr("port "+strconv.Itoa(portInt)+" not in allowed_ports"))
		errJSON(w, http.StatusBadRequest,
			"Port "+strconv.Itoa(portInt)+" is not in the allowed_ports whitelist")
		return
	}

	// Name charset allowlist (SR-1): group names flow into firewall comments /
	// identifiers, so confine them up front. (Not a separate branch in app.py's
	// route body, but enforced by the firewall layer it delegates to; surfaced
	// here as a clear 400 before the DB write.)
	if !firewall.ValidName(name) {
		errJSON(w, http.StatusBadRequest, "Invalid group name")
		return
	}

	// One group per (port, proto).
	if dup, derr := s.db.GetGroupByPortProto(portInt, proto); derr == nil && dup != nil {
		errJSON(w, http.StatusConflict,
			"Port "+strconv.Itoa(portInt)+"/"+proto+" is already used by group '"+dup.Name+"'")
		return
	}

	id, err := s.db.CreateGroup(name, portInt, proto)
	if err != nil {
		if isUniqueViolation(err) {
			// Two UNIQUE constraints can fire: groups.name and the (port,proto)
			// index. Name the real cause, mirroring app.py.
			if dup, _ := s.db.GetGroupByPortProto(portInt, proto); dup != nil {
				errJSON(w, http.StatusConflict, "Port "+strconv.Itoa(portInt)+"/"+proto+" is already in use")
				return
			}
			errJSON(w, http.StatusConflict, "Group '"+name+"' already exists")
			return
		}
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	_ = s.db.LogAudit(user.Username, "group_add", strPtr(name),
		strPtr("port="+strconv.Itoa(portInt)+" proto="+proto))
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok": true, "id": id, "name": name, "port": portInt, "proto": proto,
	})
}

// adminDeleteGroup deletes a group and cleans up UFW rules for its members (admin
// + step-up). Mirrors app.py admin_delete_group(): 404 if missing, remove each
// online member's rule, then delete + audit.
func (s *Server) adminDeleteGroup(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	body := readJSON(r)
	if s.stepUp(w, r, user, body) {
		return
	}
	groupID, okID := pathInt(r, "group_id")
	if !okID {
		errJSON(w, http.StatusNotFound, "Group not found")
		return
	}
	group, err := s.db.GetGroup(groupID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if group == nil {
		errJSON(w, http.StatusNotFound, "Group not found")
		return
	}
	members, err := s.groupMembers(groupID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	for _, m := range members {
		if m.CurrentIP != nil && *m.CurrentIP != "" {
			_ = s.fw.RemoveRule(*m.CurrentIP, group.Port, m.Username, group.Proto, group.Name)
		}
	}
	if err := s.db.DeleteGroup(groupID); err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	_ = s.db.LogAudit(user.Username, "group_del", strPtr(group.Name), nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": groupID})
}

// groupMembers returns the (username, current_ip) of every member of a group, for
// the rule-cleanup pass adminDeleteGroup runs. The db package has no dedicated
// GetGroupMembers, so this issues the equivalent JOIN directly (mirrors the
// Python db.get_group_members shape used by the route).
func (s *Server) groupMembers(groupID int64) ([]db.User, error) {
	rows, err := s.db.Conn().Query(
		`SELECT u.username, u.current_ip FROM user_group_membership m
		 JOIN users u ON u.id = m.user_id WHERE m.group_id=?`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []db.User
	for rows.Next() {
		var u db.User
		var ip sql.NullString // current_ip is nullable; scan via NullString
		if err := rows.Scan(&u.Username, &ip); err != nil {
			return nil, err
		}
		if ip.Valid {
			v := ip.String
			u.CurrentIP = &v
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ---- Audit ---- //

// adminListAudit returns recent audit entries newest-first (admin only). The
// limit query param defaults to 100 and is clamped to 1..1000, mirroring app.py
// admin_list_audit(). Each row serializes to {id,actor,action,target,detail,
// created_at} with target/detail as null when absent.
func (s *Server) adminListAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n != 0 {
			limit = n
		}
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 1000 {
		limit = 1000
	}
	entries, err := s.db.ListAudit(limit)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		var target any = nil
		if e.Target != nil {
			target = *e.Target
		}
		var detail any = nil
		if e.Detail != nil {
			detail = *e.Detail
		}
		out = append(out, map[string]any{
			"id": e.ID, "actor": e.Actor, "action": e.Action,
			"target": target, "detail": detail, "created_at": e.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "audit": out})
}

// ---- helpers ---- //

// b2iJSON renders a Go bool as the 0/1 integer the Python sqlite rows carried, so
// the web client's `is_admin`/`totp_enabled`/`enabled` truthiness checks see the
// same shape they did against Flask (which serialized the raw INTEGER column).
func b2iJSON(b bool) int {
	if b {
		return 1
	}
	return 0
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// isUniqueViolation reports whether err is a SQLite UNIQUE/PRIMARY KEY constraint
// failure — the Go analogue of catching sqlite3.IntegrityError for the duplicate
// branches. modernc.org/sqlite surfaces these with a message containing
// "UNIQUE constraint failed"; matching on the lowered message keeps this
// driver-agnostic without importing the driver's error type.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}
