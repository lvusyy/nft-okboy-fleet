package firewall

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"nft-okboy-fleet/internal/db"
)

// PortProto is the (port, proto) a group exposes — the Go analogue of the
// Python “enabled_groups“ value tuple “(port, proto)“.
type PortProto struct {
	Port  int
	Proto string
}

// Anomaly is the suspicious-IP-churn report from CheckIPAnomaly (nil == normal),
// mirroring the dict ufw_ops.check_ip_anomaly returned.
type Anomaly struct {
	Changes   int      // ip_change rows in the window
	Window    int      // the window, in seconds
	UniqueIPs int      // distinct IPs seen (changes + current)
	IPs       []string // those distinct IPs
}

// Manager is the reconcile/anomaly/cleanup POLICY layer, ported 1:1 from
// ufw_ops.UFWManager. It owns nothing raw: every firewall mutation goes through a
// FirewallBackend, and all user/IP state lives in the db.DB — so the policy is
// unit-testable with a MockBackend, no root or nft binary required.
type Manager struct {
	be     FirewallBackend
	db     *db.DB
	prefix string
}

// NewManager wires a backend, the DB, and the rule-comment prefix together.
func NewManager(be FirewallBackend, database *db.DB, prefix string) *Manager {
	return &Manager{be: be, db: database, prefix: prefix}
}

// AddRule is a thin wrapper over the backend so logging and the precise-comment
// convention live in one place (mirrors ufw_ops.add_rule).
func (m *Manager) AddRule(ip string, port int, user, proto, group string) error {
	if err := m.be.AddRule(ip, port, user, proto, group); err != nil {
		return err
	}
	log.Printf("firewall: added rule %s -> port %d/%s (%s)",
		ip, port, proto, commentFor(m.prefix, user, group))
	return nil
}

// RemoveRule is a thin wrapper over the backend's precise (comment-keyed) delete
// (mirrors ufw_ops.remove_rule). A missing rule is not an error: the backend
// no-ops it, exactly like the Python "may not exist" warning path.
func (m *Manager) RemoveRule(ip string, port int, user, proto, group string) error {
	if err := m.be.RemoveRule(ip, port, user, proto, group); err != nil {
		return err
	}
	log.Printf("firewall: removed rule %s -> port %d/%s (%s)",
		ip, port, proto, commentFor(m.prefix, user, group))
	return nil
}

// Reconcile idempotently aligns this user's firewall rules with their
// enabled groups at clientIP — the direct port of reconcile_user_rules.
//
// It performs ONE ListUserRules(user) pass, then:
//   - For each enabled group, adds an allow rule if one for clientIP is missing
//     (comment "<prefix>:<user>:<group>") and records the group in added.
//   - Scans the listed rules and drops every rule that is STALE — its group is no
//     longer enabled OR its IP differs from clientIP — via DeleteByHandle,
//     recording the group in removed. This repairs stale memberships, concurrent
//     membership changes, cross-group collisions, AND stale old-IP rules for
//     groups that are still enabled.
//
// The group name is parsed out of each rule's comment ("<prefix>:<user>:<group>").
func (m *Manager) Reconcile(user, clientIP string, enabled map[string]PortProto) (added, removed []string, err error) {
	// Single pass: fetch all of this user's rules once (fixes N+1).
	rules, err := m.be.ListUserRules(user)
	if err != nil {
		return nil, nil, err
	}

	// Index existing rules by their identity tuple for the membership test.
	type key struct {
		ip    string
		port  int
		proto string
		group string
	}
	existing := make(map[key]bool, len(rules))
	for _, r := range rules {
		existing[key{r.IP, r.Port, r.Proto, m.groupFromComment(user, r.Comment)}] = true
	}

	// Add missing rules for every enabled group (per-group proto preserved).
	var addErrs []error
	for group, pp := range enabled {
		if !existing[key{clientIP, pp.Port, pp.Proto, group}] {
			// Isolate per-group failures (transient nft lock, bad port, ...) so one
			// failing add does not abort the whole reconcile and skip the stale-rule
			// cleanup below — symmetric with the removal loop. Stale old-IP rules
			// MUST still be removed even when a new add fails. The failure is
			// COLLECTED (not swallowed) and surfaced after the full pass so the
			// caller — e.g. the knock handler — can report it instead of falsely
			// claiming success with a port that was never opened.
			if aerr := m.AddRule(clientIP, pp.Port, user, pp.Proto, group); aerr != nil {
				log.Printf("firewall: reconcile failed to add rule for group %s (%d/%s): %v",
					group, pp.Port, pp.Proto, aerr)
				addErrs = append(addErrs, fmt.Errorf("add %s (%d/%s): %w", group, pp.Port, pp.Proto, aerr))
				continue
			}
			added = append(added, group)
		}
	}

	// Remove stale rules: group no longer enabled, OR bound to an old IP.
	for _, r := range rules {
		group := m.groupFromComment(user, r.Comment)
		if group == "" {
			continue
		}
		_, stillEnabled := enabled[group]
		stale := !stillEnabled || r.IP != clientIP
		if stale {
			if derr := m.be.DeleteByHandle(r.Handle); derr != nil {
				log.Printf("firewall: reconcile failed to remove stale rule handle=%d (%s): %v",
					r.Handle, r.Comment, derr)
				continue
			}
			removed = append(removed, group)
		}
	}

	if len(added) > 0 || len(removed) > 0 {
		log.Printf("firewall: reconciled rules for %s@%s: added=%v removed=%v",
			user, clientIP, added, removed)
	}
	// Surface any per-group add failures AFTER the stale-removal pass has run, so
	// the self-heal still happens but the caller learns a rule could not be
	// applied. errors.Join(nil...) is nil, so the success path is unchanged.
	return added, removed, errors.Join(addErrs...)
}

// CheckIPAnomaly detects suspicious IP-change churn that suggests credential
// sharing — the port of check_ip_anomaly. It returns nil when normal, or an
// *Anomaly when the change count in the window EXCEEDS maxChanges.
//
// NOTE on the boundary: the Python code triggers on “changes >= max_changes“,
// but the package contract here specifies “changes > maxChanges“. We honour the
// Go contract (strictly greater) so callers passing maxChanges get one extra
// change of slack. See the summary's assumptions.
func (m *Manager) CheckIPAnomaly(user string, windowSec, maxChanges int) *Anomaly {
	u, err := m.db.GetUserByUsername(user)
	if err != nil || u == nil {
		return nil
	}
	changes, err := m.db.CountRecentIPChanges(user, windowSec)
	if err != nil {
		log.Printf("firewall: CheckIPAnomaly count failed for %s: %v", user, err)
		return nil
	}
	// Match the Python reference: anomaly triggers at changes >= maxChanges.
	if changes < maxChanges {
		return nil
	}
	ips, err := m.db.GetRecentIPChangeIPs(user, windowSec)
	if err != nil {
		log.Printf("firewall: CheckIPAnomaly ip-list failed for %s: %v", user, err)
		return nil
	}
	// Deduplicate, preserving first-seen order, and fold in the current IP.
	seen := make(map[string]bool, len(ips)+1)
	unique := make([]string, 0, len(ips)+1)
	for _, ip := range ips {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			unique = append(unique, ip)
		}
	}
	if u.CurrentIP != nil && *u.CurrentIP != "" && !seen[*u.CurrentIP] {
		seen[*u.CurrentIP] = true
		unique = append(unique, *u.CurrentIP)
	}
	return &Anomaly{
		Changes:   changes,
		Window:    windowSec,
		UniqueIPs: len(unique),
		IPs:       unique,
	}
}

// CleanupStale removes firewall rules for users who have not knocked within
// maxAgeSec — the port of cleanup_stale.
//
// ugp maps username -> []GroupPort of each user's ENABLED groups (the caller
// builds it from the DB via db.GetAllUserGroupPorts), so cleanup removes only the
// ports a user is actually authorized for — no orphaned rules on custom group
// ports. For each stale user with a recorded IP we precise-delete every
// (group, port, proto) rule, then clear their DB state. Returns the removed
// usernames.
func (m *Manager) CleanupStale(maxAgeSec int, ugp map[string][]db.GroupPort) ([]string, error) {
	users, err := m.db.ListUsers()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	var removed []string
	for i := range users {
		u := users[i]
		if u.LastKnock == nil {
			continue
		}
		if now-*u.LastKnock <= int64(maxAgeSec) {
			continue
		}
		if u.CurrentIP != nil && *u.CurrentIP != "" {
			for _, gp := range ugp[u.Username] {
				if rerr := m.RemoveRule(*u.CurrentIP, gp.Port, u.Username, gp.Proto, gp.Group); rerr != nil {
					log.Printf("firewall: cleanup failed to remove %s rule for %s: %v",
						gp.Group, u.Username, rerr)
				}
			}
		}
		if cerr := m.db.ClearUserState(u.ID); cerr != nil {
			return removed, cerr
		}
		removed = append(removed, u.Username)
		log.Printf("firewall: cleaned up stale user %s (last knock %ds ago)",
			u.Username, now-*u.LastKnock)
	}
	return removed, nil
}

// ListManaged returns every rule the backend manages (all "<prefix>:" rules),
// for the CLI list / sync-recovery paths.
func (m *Manager) ListManaged() ([]Rule, error) {
	return m.be.ListManaged()
}

// groupFromComment extracts the group from a comment "<prefix>:<user>:<group>".
// It returns "" when the comment lacks the "<prefix>:<user>:" prefix or carries
// no group suffix (the legacy "<prefix>:<user>" form), matching the Python
// suffix.split(":", 1)[0] logic.
func (m *Manager) groupFromComment(user, comment string) string {
	want := m.prefix + ":" + user + ":"
	if !strings.HasPrefix(comment, want) {
		return ""
	}
	suffix := comment[len(want):]
	if suffix == "" {
		return ""
	}
	if i := strings.IndexByte(suffix, ':'); i >= 0 {
		return suffix[:i]
	}
	return suffix
}

// endpoint renders "ip:port/proto" for log/Calls lines (test introspection).
func endpoint(ip string, port int, proto string) string {
	return fmt.Sprintf("%s:%d/%s", ip, port, proto)
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
