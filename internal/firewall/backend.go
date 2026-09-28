// Package firewall mutates the host firewall to allow authenticated client IPs
// to reach the ports of the groups they belong to.
//
// The design separates two concerns the Python UFWManager conflated:
//   - FirewallBackend: the THIN raw-mutation layer (nftables in prod, a Mock for
//     unit tests on non-Linux dev hosts).
//   - Manager (manager.go): the reconcile/anomaly/cleanup POLICY, ported 1:1 from
//     ufw_ops.py, depending only on the interface so it is testable without root
//     or an nft binary.
package firewall

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// ErrInactive: the firewall is not enforcing (ufw is disabled). ufw then lists no
// rules although it keeps them saved, so nothing can be listed, removed or
// reconciled reliably until it is enabled again.
var ErrInactive = errors.New("ufw is inactive: nft-okboy cannot list or change its rules until ufw is enabled (allow SSH first)")

// ErrHostRule: AddRule left the host's own rule for the same source, port and
// protocol in charge instead of adding a managed one over it (ufw would have
// rewritten that rule: a host ALLOW would become nft-okboy's, a host DENY an
// ALLOW). Not a failure: the host rule decides that source's access.
var ErrHostRule = errors.New("a host rule for the same source, port and protocol decides this access")

// HostRuleError is the ErrHostRule of UfwBackend.AddRule, with the host rule's
// action: ALLOW, DENY, REJECT or LIMIT.
type HostRuleError struct{ Action string }

func (e *HostRuleError) Error() string { return ErrHostRule.Error() + " (" + e.Action + ")" }

// Is makes errors.Is(err, ErrHostRule) hold.
func (e *HostRuleError) Is(target error) bool { return target == ErrHostRule }

// Rule is the backend-neutral view of one managed allow rule. It mirrors the
// dict that ufw_ops.list_rules_by_comment returned; Handle is the nftables rule
// handle (the stable analogue of UFW's shifting rule "number"), used for precise
// deletion.
type Rule struct {
	Handle  int64
	IP      string
	Port    int
	Proto   string
	User    string
	Group   string
	Comment string // "<prefix>:<user>:<group>" — traceability + precise-delete key
}

// FirewallBackend is the raw firewall-mutation layer. Semantics mirror ufw_ops:
//
//   - AddRule appends an allow rule commented "<prefix>:<user>:<group>".
//   - RemoveRule deletes the rule matching ip/port/proto AND that exact comment
//     (precise — never collides with another group on the same ip/port).
//   - ListUserRules returns every rule whose comment starts "<prefix>:<user>:" in
//     ONE backend call (the N+1-avoiding single pass of reconcile_user_rules).
//   - DeleteByHandle removes one rule by handle (reconcile drops stale rules it
//     located in the single pass).
//   - ListManaged returns all "<prefix>:" rules (CLI list / sync recovery).
//   - EnsureBase idempotently creates the table+chain (nft only; Mock is a no-op).
type FirewallBackend interface {
	EnsureBase() error
	AddRule(ip string, port int, user, proto, group string) error
	RemoveRule(ip string, port int, user, proto, group string) error
	ListUserRules(user string) ([]Rule, error)
	DeleteByHandle(handle int64) error
	ListManaged() ([]Rule, error)
}

// Guard is implemented by a backend that must itself close its managed ports to
// everyone its allow rules do not admit. nftables needs one: nft-okboy's table
// is just one base chain on the input hook, so accept rules alone restrict
// nothing — unmatched packets meet the chain's accept policy, and an accept is
// not final anyway (a later base chain may still drop). ufw needs no guard: UFW's
// default-deny already closes every port the allow rules leave shut.
type Guard interface {
	// SyncGuard makes the guard drop new connections to exactly ports (from any
	// source no allow rule accepted; for UDP, every datagram); an empty ports
	// removes the guard.
	SyncGuard(ports []PortProto) error
}

// nameRe is the SR-1 charset allowlist for usernames and group names. These
// strings flow into nftables rule comments and identifiers, so confining them to
// a safe charset (no spaces, quotes, backslashes, ':', ';', '{', '}', '#',
// newlines) eliminates the whole comment/identifier-injection class up front —
// independent of the JSON-escaped write path. Max 64; must start alphanumeric.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// ValidName reports whether s is an acceptable username or group name.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// CanonicalIP returns s as one canonical IP literal ("203.0.113.7", "2001:db8::1";
// an IPv4-mapped IPv6 address becomes plain IPv4), or "" when s is anything else:
// a CIDR, a zone-scoped address, a hostname, or a firewall keyword like "any".
// Only single addresses may reach a rule — ufw reads "any" or "0.0.0.0/0" as
// "everyone", and nft would resolve a hostname.
func CanonicalIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// checkRule is the backends' last line of defence: whatever the caller passed,
// a managed rule is one IP, a port in 1..65535 and tcp or udp.
func checkRule(ip string, port int, proto string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("refusing rule for %q: not a single IP address", ip)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("refusing rule for port %d: out of range", port)
	}
	if proto != "tcp" && proto != "udp" {
		return fmt.Errorf("refusing rule for protocol %q: must be tcp or udp", proto)
	}
	return nil
}

// commentFor builds the rule comment exactly like ufw_ops.add_rule:
//
//	"<prefix>:<user>"          when group == ""
//	"<prefix>:<user>:<group>"  otherwise
func commentFor(prefix, user, group string) string {
	if group == "" {
		return prefix + ":" + user
	}
	return prefix + ":" + user + ":" + group
}

// Comment is the exported form of commentFor, for callers outside this package
// (the hub's desired-state projection and the agent) that must build the same
// "<prefix>:<user>:<group>" managed-rule comment the backends key on.
func Comment(prefix, user, group string) string { return commentFor(prefix, user, group) }
