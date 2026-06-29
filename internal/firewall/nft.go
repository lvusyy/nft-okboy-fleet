package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// nftTimeout bounds every nft invocation; a wedged firewall must not hang a knock.
const nftTimeout = 30 * time.Second

// NftConfig configures the real nftables backend. Defaults (filled by
// NewNftBackend) are table "ufw_okboy", chain "input", priority -150.
type NftConfig struct {
	Prefix   string // rule-comment prefix, e.g. "ufw-okboy"
	Table    string // inet table name
	Chain    string // base chain name
	Priority int    // hook priority (negative = earlier; -150 sits before most)
}

// Compile-time guarantee NftBackend stays a complete FirewallBackend.
var _ FirewallBackend = (*NftBackend)(nil)

// NftBackend mutates real nftables by shelling out to `nft` with its JSON
// program format. It owns a dedicated `inet` table+chain whose policy is ACCEPT
// and which only ever appends accept rules — so it coexists with k8s/host
// firewalls in their own tables and NEVER drops traffic of its own accord.
//
// Injection safety: writes are built as Go structs, json.Marshal'd, and piped to
// `nft -j -f -` on STDIN. User data is never concatenated into a shell string or
// passed as argv, and ValidName has already confined usernames/groups to a safe
// charset upstream — so the whole comment/identifier-injection class is closed.
type NftBackend struct {
	cfg     NftConfig
	nftPath string
}

// NewNftBackend resolves the `nft` binary and applies config defaults. It does
// NOT touch the firewall; call EnsureBase for that.
func NewNftBackend(cfg NftConfig) (*NftBackend, error) {
	if cfg.Prefix == "" {
		cfg.Prefix = "ufw-okboy"
	}
	if cfg.Table == "" {
		cfg.Table = "ufw_okboy"
	}
	if cfg.Chain == "" {
		cfg.Chain = "input"
	}
	if cfg.Priority == 0 {
		cfg.Priority = -150
	}
	path, err := exec.LookPath("nft")
	if err != nil {
		return nil, fmt.Errorf("nft binary not found in PATH: %w", err)
	}
	return &NftBackend{cfg: cfg, nftPath: path}, nil
}

// ------------------------------------------------------------------ //
//  JSON program scaffolding (libnftables -j schema)
// ------------------------------------------------------------------ //

// nftProgram is the top-level {"nftables":[ ...commands... ]} document.
type nftProgram struct {
	Nftables []any `json:"nftables"`
}

// runJSON pipes a JSON program to `nft -j -f -` (a single atomic transaction).
func (n *NftBackend) runJSON(prog nftProgram) error {
	payload, err := json.Marshal(prog)
	if err != nil {
		return fmt.Errorf("marshal nft program: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), nftTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, n.nftPath, "-j", "-f", "-")
	cmd.Stdin = bytes.NewReader(payload)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("nft timed out after %s", nftTimeout)
		}
		return fmt.Errorf("nft failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// runJSONRead runs a read command (`nft -j -a <args...>`) and returns stdout for
// unmarshalling. -a includes rule handles in the output.
func (n *NftBackend) runJSONRead(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nftTimeout)
	defer cancel()
	full := append([]string{"-j", "-a"}, args...)
	cmd := exec.CommandContext(ctx, n.nftPath, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("nft timed out after %s", nftTimeout)
		}
		// A missing chain (nothing to list yet) is reported via stderr; treat the
		// "No such file or directory" case as an empty set, not an error.
		msg := strings.ToLower(stderr.String())
		if strings.Contains(msg, "no such file") || strings.Contains(msg, "does not exist") {
			return nil, nil
		}
		return nil, fmt.Errorf("nft read failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// ------------------------------------------------------------------ //
//  EnsureBase
// ------------------------------------------------------------------ //

// EnsureBase idempotently creates the inet table and the base chain (hook input,
// policy accept) in one transaction. `add` is idempotent in nftables — re-adding
// an existing table/chain with the same spec is a no-op — so this is safe to call
// on every startup. Policy ACCEPT + accept-only rules means this table can never
// black-hole traffic that other tables would have allowed.
func (n *NftBackend) EnsureBase() error {
	prog := nftProgram{Nftables: []any{
		map[string]any{
			"add": map[string]any{
				"table": map[string]any{
					"family": "inet",
					"name":   n.cfg.Table,
				},
			},
		},
		map[string]any{
			"add": map[string]any{
				"chain": map[string]any{
					"family": "inet",
					"table":  n.cfg.Table,
					"name":   n.cfg.Chain,
					"type":   "filter",
					"hook":   "input",
					"prio":   n.cfg.Priority,
					"policy": "accept",
				},
			},
		},
	}}
	return n.runJSON(prog)
}

// ------------------------------------------------------------------ //
//  Writes
// ------------------------------------------------------------------ //

// AddRule appends an accept rule matching `ip saddr <ip>` (ip6 for v6) and
// `<proto> dport <port>`, carrying the comment "<prefix>:<user>:<group>".
func (n *NftBackend) AddRule(ip string, port int, user, proto, group string) error {
	expr := n.matchExpr(ip, port, proto)
	expr = append(expr, map[string]any{"accept": nil})

	rule := map[string]any{
		"family":  "inet",
		"table":   n.cfg.Table,
		"chain":   n.cfg.Chain,
		"comment": commentFor(n.cfg.Prefix, user, group),
		"expr":    expr,
	}
	prog := nftProgram{Nftables: []any{
		map[string]any{"add": map[string]any{"rule": rule}},
	}}
	return n.runJSON(prog)
}

// RemoveRule lists the user's rules, finds the one whose ip/port/proto AND comment
// match (the precise, cross-group-safe delete), and deletes it by handle. A miss
// is not an error — the caller's reconcile re-adds anything still needed.
func (n *NftBackend) RemoveRule(ip string, port int, user, proto, group string) error {
	rules, err := n.ListUserRules(user)
	if err != nil {
		return err
	}
	want := commentFor(n.cfg.Prefix, user, group)
	for _, r := range rules {
		if r.IP == ip && r.Port == port && r.Proto == proto && r.Comment == want {
			return n.DeleteByHandle(r.Handle)
		}
	}
	return nil
}

// DeleteByHandle removes one rule by its handle in a single transaction.
func (n *NftBackend) DeleteByHandle(handle int64) error {
	prog := nftProgram{Nftables: []any{
		map[string]any{
			"delete": map[string]any{
				"rule": map[string]any{
					"family": "inet",
					"table":  n.cfg.Table,
					"chain":  n.cfg.Chain,
					"handle": handle,
				},
			},
		},
	}}
	return n.runJSON(prog)
}

// matchExpr builds the saddr + dport match expressions for a rule. IPv4 uses
// `ip saddr`, IPv6 `ip6 saddr`; detection is net.ParseIP plus a ':' check.
func (n *NftBackend) matchExpr(ip string, port int, proto string) []any {
	saddrProto := "ip"
	if isIPv6(ip) {
		saddrProto = "ip6"
	}
	return []any{
		map[string]any{
			"match": map[string]any{
				"op": "==",
				"left": map[string]any{
					"payload": map[string]any{
						"protocol": saddrProto,
						"field":    "saddr",
					},
				},
				"right": ip,
			},
		},
		map[string]any{
			"match": map[string]any{
				"op": "==",
				"left": map[string]any{
					"payload": map[string]any{
						"protocol": proto,
						"field":    "dport",
					},
				},
				"right": port,
			},
		},
	}
}

// ------------------------------------------------------------------ //
//  Reads
// ------------------------------------------------------------------ //

// ListUserRules returns every managed rule whose comment starts
// "<prefix>:<user>:" in one `nft list chain` pass.
func (n *NftBackend) ListUserRules(user string) ([]Rule, error) {
	return n.listFiltered(n.cfg.Prefix + ":" + user + ":")
}

// ListManaged returns every managed rule whose comment starts "<prefix>:".
func (n *NftBackend) ListManaged() ([]Rule, error) {
	return n.listFiltered(n.cfg.Prefix + ":")
}

// listFiltered lists the base chain and keeps the rules whose comment has the
// given prefix. Parsing is deliberately tolerant: a rule with an unexpected
// shape is skipped rather than failing the whole list.
func (n *NftBackend) listFiltered(commentPrefix string) ([]Rule, error) {
	out, err := n.runJSONRead("list", "chain", "inet", n.cfg.Table, n.cfg.Chain)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("parse nft list output: %w", err)
	}
	var rules []Rule
	for _, item := range doc.Nftables {
		raw, ok := item["rule"]
		if !ok {
			continue
		}
		var jr nftRule
		if err := json.Unmarshal(raw, &jr); err != nil {
			continue // tolerant: skip malformed rule objects
		}
		if !strings.HasPrefix(jr.Comment, commentPrefix) {
			continue
		}
		r := Rule{Handle: jr.Handle, Comment: jr.Comment}
		parseExpr(jr.Expr, &r)
		// Recover user/group from the comment "<prefix>:<user>:<group>".
		r.User, r.Group = splitComment(n.cfg.Prefix, jr.Comment)
		rules = append(rules, r)
	}
	return rules, nil
}

// nftRule is the subset of a libnftables `rule` object we consume.
type nftRule struct {
	Family  string            `json:"family"`
	Table   string            `json:"table"`
	Chain   string            `json:"chain"`
	Handle  int64             `json:"handle"`
	Comment string            `json:"comment"`
	Expr    []json.RawMessage `json:"expr"`
}

// parseExpr walks a rule's expr array, filling r.IP/Port/Proto from the saddr and
// dport match statements. Anything it does not recognise is ignored.
func parseExpr(exprs []json.RawMessage, r *Rule) {
	for _, e := range exprs {
		var m struct {
			Match *struct {
				Left struct {
					Payload *struct {
						Protocol string `json:"protocol"`
						Field    string `json:"field"`
					} `json:"payload"`
				} `json:"left"`
				Right json.RawMessage `json:"right"`
			} `json:"match"`
		}
		if err := json.Unmarshal(e, &m); err != nil || m.Match == nil || m.Match.Left.Payload == nil {
			continue
		}
		p := m.Match.Left.Payload
		switch p.Field {
		case "saddr":
			// right is the matched address string (may also be an object/set in
			// exotic rules — we only handle the plain string our writer emits).
			var ip string
			if json.Unmarshal(m.Match.Right, &ip) == nil {
				r.IP = ip
			}
		case "dport":
			var port int
			if json.Unmarshal(m.Match.Right, &port) == nil {
				r.Port = port
			}
			// p.Protocol here is the L4 proto carrying dport (tcp/udp).
			if p.Protocol == "tcp" || p.Protocol == "udp" {
				r.Proto = p.Protocol
			}
		}
	}
}

// splitComment recovers (user, group) from "<prefix>:<user>:<group>". A comment
// missing the prefix yields ("",""); the legacy "<prefix>:<user>" form yields
// (user, "").
func splitComment(prefix, comment string) (user, group string) {
	want := prefix + ":"
	if !strings.HasPrefix(comment, want) {
		return "", ""
	}
	rest := comment[len(want):]
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		return rest[:i], rest[i+1:]
	}
	return rest, ""
}

// isIPv6 reports whether ip is an IPv6 literal.
func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil && strings.Contains(ip, ":")
}
