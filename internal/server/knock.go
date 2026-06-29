package server

import (
	"fmt"
	"net/http"

	"nft-okboy-fleet/internal/auth"
	"nft-okboy-fleet/internal/firewall"
	"nft-okboy-fleet/internal/static"
)

// authUser runs the HMAC check for the client endpoints, returning the
// authenticated username or "" with the response already written (401). It is the
// Go form of app.py's _auth() + the inline 401 every client handler does.
func (s *Server) authUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	username, err := auth.VerifyHMAC(s.db, r.Header.Get("Authorization"), s.cfg.SignatureTTL, s.clientIP(r))
	if err != "" {
		errJSON(w, http.StatusUnauthorized, err)
		return "", false
	}
	return username, true
}

// serveIndex serves the embedded single-file web client for "/" and "/static/...".
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(static.Index)
}

// knock registers or updates the caller's IP in the firewall allowlist. It is a
// faithful port of app.py knock(), preserving the exact order that makes the flow
// self-healing and torn-write-safe:
//
//  1. authenticate (401 on failure);
//  2. client-IP guard — reject "" or "127.0.0.1" with 400 (a direct, un-proxied
//     caller cannot be allowlisted);
//  3. build the enabled-group map and Reconcile FIRST (the idempotent single pass
//     that adds the client_ip rules and removes every rule whose IP differs / whose
//     group is no longer enabled — the comprehensive self-heal);
//  4. RecordIPChange atomically claims the IP and returns the TRUE superseded IP;
//  5. if unchanged → heartbeat; else targeted removal of the prior IP's rules per
//     enabled group, an anomaly check (optional "warning"), then the updated body.
func (s *Server) knock(w http.ResponseWriter, r *http.Request) {
	username, ok := s.authUser(w, r)
	if !ok {
		return
	}

	clientIP := s.clientIP(r)
	if clientIP == "" || clientIP == "127.0.0.1" {
		errJSON(w, http.StatusBadRequest,
			"Cannot determine real client IP. Check Nginx X-Real-IP header.")
		return
	}

	user, derr := s.db.GetUserByUsername(username)
	if derr != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if user == nil {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}

	enabledGroups, derr := s.db.GetUserGroups(user.ID, true)
	if derr != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	enabled := make(map[string]firewall.PortProto, len(enabledGroups))
	for _, g := range enabledGroups {
		enabled[g.Name] = firewall.PortProto{Port: g.Port, Proto: g.Proto}
	}

	// Reconcile FIRST: align the firewall with the user's enabled groups in one
	// numbered pass (adds client_ip rules, removes stale/cross-knock orphans).
	if _, _, ferr := s.fw.Reconcile(username, clientIP, enabled); ferr != nil {
		errJSON(w, http.StatusInternalServerError, "Firewall reconcile failed")
		return
	}

	// Atomic state write: read prior IP and write current_ip+last_knock (+ an
	// ip_change row only when it actually changed) in ONE transaction. The
	// returned value is the TRUE superseded IP under concurrent knocks.
	oldIP, derr := s.db.RecordIPChange(user.ID, username, clientIP)
	if derr != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}

	// IP unchanged: reconcile refreshed the rules and the write bumped the
	// timestamp — report a heartbeat.
	if oldIP != nil && *oldIP == clientIP {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"ip":      clientIP,
			"changed": false,
			"message": "IP unchanged, heartbeat recorded",
		})
		return
	}

	// IP changed: targeted removal of any rule still bound to the prior IP for
	// each enabled group, driven by the true superseded IP from the atomic swap.
	if oldIP != nil {
		for _, g := range enabledGroups {
			_ = s.fw.RemoveRule(*oldIP, g.Port, username, g.Proto, g.Name)
		}
	}

	// Anomaly check (possible credential sharing) — optional "warning" field.
	var warning string
	if a := s.fw.CheckIPAnomaly(username, s.cfg.AnomalyWindow, s.cfg.AnomalyMaxChanges); a != nil {
		warning = fmt.Sprintf(
			"Suspicious activity: %d IP changes from %d unique IPs in the last %d minutes. Possible credential sharing.",
			a.Changes, a.UniqueIPs, s.cfg.AnomalyWindow/60,
		)
	}

	groupNames := make([]string, 0, len(enabledGroups))
	for _, g := range enabledGroups {
		groupNames = append(groupNames, g.Name)
	}

	resp := map[string]any{
		"ok":      true,
		"ip":      clientIP,
		"changed": true,
		"old_ip":  oldIP, // nil → JSON null, matching Python's old_ip being None for a new IP
		"groups":  groupNames,
		"message": "Firewall rules updated",
	}
	if warning != "" {
		resp["warning"] = warning
	}
	writeJSON(w, http.StatusOK, resp)
}

// status returns the caller's current registration state. Mirrors app.py status():
// the spread state ({ip, last_knock, ip_changes_recent}) is reconstructed directly
// from the DB (user row + a 24h ip_change count) rather than via a firewall helper,
// since the state is wholly DB-derived. is_admin / totp_enabled come from the user
// row; enabled_groups lists the user's currently-enabled groups.
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	username, ok := s.authUser(w, r)
	if !ok {
		return
	}
	user, derr := s.db.GetUserByUsername(username)
	if derr != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}

	// state defaults (no such user → the Python get_user_state miss shape).
	var ip any = nil
	var lastKnock any = nil
	ipChangesRecent := 0
	isAdmin := false
	totpEnabled := false
	enabledGroups := []map[string]any{}

	if user != nil {
		if user.CurrentIP != nil {
			ip = *user.CurrentIP
		}
		if user.LastKnock != nil {
			lastKnock = *user.LastKnock
		}
		if n, e := s.db.CountRecentIPChanges(username, 86400); e == nil {
			ipChangesRecent = n
		}
		isAdmin = user.IsAdmin
		totpEnabled = user.TOTPEnabled
		groups, e := s.db.GetUserGroups(user.ID, true)
		if e == nil {
			for _, g := range groups {
				enabledGroups = append(enabledGroups, map[string]any{
					"name": g.Name, "port": g.Port, "proto": g.Proto,
				})
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"username":          username,
		"is_admin":          isAdmin,
		"totp_enabled":      totpEnabled,
		"enabled_groups":    enabledGroups,
		"ip":                ip,
		"last_knock":        lastKnock,
		"ip_changes_recent": ipChangesRecent,
	})
}

// myGroups returns the caller's groups with enabled flags (for the self-auth UI).
// Both enabled and disabled memberships are returned so the user can see /
// re-enable previously-authorized groups; groups they were never a member of are
// NOT listed (those require an admin grant). Mirrors app.py my_groups()'s raw
// JOIN, item shape {id, name, port, proto, enabled}.
func (s *Server) myGroups(w http.ResponseWriter, r *http.Request) {
	username, ok := s.authUser(w, r)
	if !ok {
		return
	}
	user, derr := s.db.GetUserByUsername(username)
	if derr != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if user == nil {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}
	rows, e := s.db.Conn().Query(
		`SELECT g.id AS id, g.name AS name, g.port AS port, g.proto AS proto, m.enabled AS enabled
		 FROM groups g JOIN user_group_membership m ON m.group_id = g.id
		 WHERE m.user_id=? ORDER BY g.name`, user.ID)
	if e != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	defer rows.Close()
	groups := []map[string]any{}
	for rows.Next() {
		var id int64
		var name, proto string
		var port, en int
		if e := rows.Scan(&id, &name, &port, &proto, &en); e != nil {
			errJSON(w, http.StatusInternalServerError, "Internal error")
			return
		}
		groups = append(groups, map[string]any{
			"id": id, "name": name, "port": port, "proto": proto, "enabled": en != 0,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "username": username, "groups": groups,
	})
}

// selfToggleMembership toggles the caller's OWN group membership (self-auth).
// Mirrors app.py self_toggle_membership(): existence check first (404), then the
// VULN-A re-enable rule (a non-admin may only RE-ENABLE a previously-authorized
// group — UserHasGroupAccess with allowReenable=true), then the DB flip and an
// immediate UFW sync (remove on disable, idempotent reconcile-add on enable).
func (s *Server) selfToggleMembership(w http.ResponseWriter, r *http.Request) {
	username, ok := s.authUser(w, r)
	if !ok {
		return
	}
	requester, derr := s.db.GetUserByUsername(username)
	if derr != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if requester == nil {
		errJSON(w, http.StatusUnauthorized, "Authenticated user not found")
		return
	}
	groupID, okID := pathInt(r, "group_id")
	if !okID {
		errJSON(w, http.StatusNotFound, "Group not found")
		return
	}

	body := readJSON(r)
	enabled, isBool := jsonBool(body, "enabled")
	if !isBool {
		errJSON(w, http.StatusBadRequest, "Request body must include 'enabled' (bool)")
		return
	}

	// Existence check FIRST (404) so a typo'd group_id is not-found, not a
	// misleading 403 (H-10).
	group, derr := s.db.GetGroup(groupID)
	if derr != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if group == nil {
		errJSON(w, http.StatusNotFound, "Group not found")
		return
	}

	// Self-enable authorization (VULN-A): re-enable only if previously authorized.
	if enabled && !auth.IsAdmin(s.db, username) {
		has, e := s.db.UserHasGroupAccess(username, groupID, true)
		if e != nil {
			errJSON(w, http.StatusInternalServerError, "Internal error")
			return
		}
		if !has {
			_ = s.db.LogAudit(username, "unauthorized_reenable_attempt",
				strPtr(fmt.Sprintf("self/%d", groupID)), strPtr("self-enable of never-authorized group"))
			errJSON(w, http.StatusForbidden,
				"Forbidden: you may only re-enable a previously authorized group. Ask an admin to grant access.")
			return
		}
	}

	if e := s.db.SetMembershipEnabled(requester.ID, groupID, enabled); e != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}

	if requester.CurrentIP != nil && *requester.CurrentIP != "" {
		ip := *requester.CurrentIP
		if !enabled {
			_ = s.fw.RemoveRule(ip, group.Port, requester.Username, group.Proto, group.Name)
		} else {
			// Idempotent add via reconcile: re-enabling an existing rule is a no-op.
			_, _, _ = s.fw.Reconcile(requester.Username, ip,
				map[string]firewall.PortProto{group.Name: {Port: group.Port, Proto: group.Proto}})
		}
	}

	_ = s.db.LogAudit(username, "self_toggle_membership",
		strPtr(fmt.Sprintf("%d/%d", requester.ID, groupID)), strPtr(fmt.Sprintf("enabled=%v", boolPy(enabled))))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "group_id": groupID, "enabled": enabled,
	})
}

// toggleMembership toggles a user's group membership and syncs UFW immediately.
// Allowed when the requester is an admin OR is toggling their own membership.
// Mirrors app.py toggle_membership(): self-vs-admin gate (403), existence checks
// first (404), the VULN-A self-enable rule, the DB flip, and the immediate sync.
func (s *Server) toggleMembership(w http.ResponseWriter, r *http.Request) {
	username, ok := s.authUser(w, r)
	if !ok {
		return
	}
	requester, derr := s.db.GetUserByUsername(username)
	if derr != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if requester == nil {
		errJSON(w, http.StatusUnauthorized, "Authenticated user not found")
		return
	}
	userID, okU := pathInt(r, "user_id")
	groupID, okG := pathInt(r, "group_id")
	if !okU || !okG {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}

	isSelf := requester.ID == userID
	if !isSelf && !auth.IsAdmin(s.db, username) {
		errJSON(w, http.StatusForbidden, "Forbidden: admin privileges or self-toggle required")
		return
	}

	body := readJSON(r)
	enabled, isBool := jsonBool(body, "enabled")
	if !isBool {
		errJSON(w, http.StatusBadRequest, "Request body must include 'enabled' (bool)")
		return
	}

	// An admin toggling ANOTHER user's membership opens/closes a firewall port
	// for someone else — a sensitive admin write, so it requires TOTP step-up
	// exactly like admin_add_membership / admin_remove_membership. Self-toggle
	// stays step-up-free (self-service, re-validated by the VULN-A rule below).
	// Body is validated BEFORE the step-up so a malformed request does not burn a
	// single-use TOTP code (replay protection would then reject the corrected
	// retry within the same time step).
	if !isSelf {
		if s.stepUp(w, r, requester, body) {
			return
		}
	}

	// Existence checks FIRST (404).
	group, derr := s.db.GetGroup(groupID)
	if derr != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if group == nil {
		errJSON(w, http.StatusNotFound, "Group not found")
		return
	}
	target, derr := s.db.GetUser(userID)
	if derr != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if target == nil {
		errJSON(w, http.StatusNotFound, "User not found")
		return
	}

	// Self-enable authorization (VULN-A).
	if isSelf && enabled && !auth.IsAdmin(s.db, username) {
		has, e := s.db.UserHasGroupAccess(username, groupID, true)
		if e != nil {
			errJSON(w, http.StatusInternalServerError, "Internal error")
			return
		}
		if !has {
			_ = s.db.LogAudit(username, "unauthorized_reenable_attempt",
				strPtr(fmt.Sprintf("%d/%d", userID, groupID)), strPtr("self-enable of never-authorized group"))
			errJSON(w, http.StatusForbidden,
				"Forbidden: you may only re-enable a group you were previously authorized for. Ask an admin to grant access.")
			return
		}
	}

	if e := s.db.SetMembershipEnabled(userID, groupID, enabled); e != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}

	if target.CurrentIP != nil && *target.CurrentIP != "" {
		ip := *target.CurrentIP
		if !enabled {
			_ = s.fw.RemoveRule(ip, group.Port, target.Username, group.Proto, group.Name)
		} else {
			_, _, _ = s.fw.Reconcile(target.Username, ip,
				map[string]firewall.PortProto{group.Name: {Port: group.Port, Proto: group.Proto}})
		}
	}

	_ = s.db.LogAudit(username, "toggle_membership",
		strPtr(fmt.Sprintf("%d/%d", userID, groupID)), strPtr(fmt.Sprintf("enabled=%v", boolPy(enabled))))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "user_id": userID, "group_id": groupID, "enabled": enabled,
	})
}

// boolPy renders a Go bool as Python's str(bool) ("True"/"False") so audit-log
// detail strings ("enabled=True") match the Python rows byte-for-byte.
func boolPy(b bool) string {
	if b {
		return "True"
	}
	return "False"
}
