package firewall

import (
	"bytes"
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ufwTimeout bounds every ufw invocation; a wedged firewall must not hang a knock.
const ufwTimeout = 30 * time.Second

// UfwConfig configures the UFW backend. Only the rule-comment prefix is needed —
// UFW owns its own table/chain structure, unlike nftables.
type UfwConfig struct {
	Prefix string // rule-comment prefix, e.g. "ufw-okboy"
}

// Compile-time guarantee UfwBackend stays a complete FirewallBackend.
var _ FirewallBackend = (*UfwBackend)(nil)

// UfwBackend mutates the host firewall through the `ufw` CLI, porting the
// semantics of the Python ufw_ops.UFWManager onto the FirewallBackend interface.
//
// Injection safety mirrors the nft backend: every argument is passed as a
// separate argv element to exec (never a shell string), and ValidName has
// already confined usernames/groups to a safe charset upstream — so the whole
// comment/identifier-injection class is closed.
//
// Handle stability: UFW rule "numbers" shift after every delete, so a number
// captured during a List is unusable as a delete key once any earlier rule is
// removed. UfwBackend therefore exposes a STABLE SYNTHETIC handle — a hash of
// the rule's identity (comment+ip+port+proto) — and DeleteByHandle re-resolves
// the CURRENT number by re-listing at delete time. This keeps the backend
// stateless and concurrency-safe (no shared handle map) while staying correct
// under number shifting.
type UfwBackend struct {
	cfg     UfwConfig
	ufwPath string
}

// NewUfwBackend resolves the `ufw` binary and applies config defaults. It does
// NOT touch the firewall; call EnsureBase for that.
func NewUfwBackend(cfg UfwConfig) (*UfwBackend, error) {
	if cfg.Prefix == "" {
		cfg.Prefix = "ufw-okboy"
	}
	path, err := exec.LookPath("ufw")
	if err != nil {
		return nil, fmt.Errorf("ufw binary not found in PATH: %w", err)
	}
	return &UfwBackend{cfg: cfg, ufwPath: path}, nil
}

// run executes `ufw <args...>` under a forced C locale (UFW's human-readable
// `status` output is otherwise localizable, which would break parsing) and a
// timeout. Returns stdout.
func (u *UfwBackend) run(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ufwTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, u.ufwPath, args...)
	// Force a stable, parseable locale regardless of the host's settings.
	cmd.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("ufw timed out after %s", ufwTimeout)
		}
		return "", fmt.Errorf("ufw %s failed: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// EnsureBase verifies ufw is functional. UFW has no table/chain to create (it
// owns its own structure), so this only confirms `ufw status` runs and warns
// when the firewall is inactive — added rules will not enforce until the
// operator enables ufw. It deliberately NEVER auto-enables: `ufw enable` sets
// the default-incoming policy to DENY, which locks the operator out unless SSH
// was allowed first (the installer handles that ordering).
func (u *UfwBackend) EnsureBase() error {
	out, err := u.run("status")
	if err != nil {
		return err
	}
	if !strings.Contains(out, "Status: active") {
		log.Printf("ufw: firewall is INACTIVE — nft-okboy rules will not enforce until `ufw enable` (allow SSH first!)")
	}
	return nil
}

// AddRule appends an allow rule:
//
//	ufw allow from <ip> to any port <port> proto <proto> comment "<prefix>:<user>:<group>"
//
// UFW selects the IPv4/IPv6 rule family from the address itself, so no explicit
// version branch is needed.
func (u *UfwBackend) AddRule(ip string, port int, user, proto, group string) error {
	comment := commentFor(u.cfg.Prefix, user, group)
	_, err := u.run("allow", "from", ip, "to", "any",
		"port", strconv.Itoa(port), "proto", proto, "comment", comment)
	return err
}

// RemoveRule deletes the rule matching ip/port/proto AND the exact comment for
// (user, group) — the precise, cross-group-safe delete. It re-lists to resolve
// the rule's CURRENT number, then `ufw --force delete <n>`. A miss is not an
// error: the caller's reconcile re-adds anything still needed.
func (u *UfwBackend) RemoveRule(ip string, port int, user, proto, group string) error {
	want := commentFor(u.cfg.Prefix, user, group)
	lines, err := u.listManagedLines()
	if err != nil {
		return err
	}
	for _, ln := range lines {
		if ln.r.IP == ip && ln.r.Port == port && ln.r.Proto == proto && ln.r.Comment == want {
			return u.deleteNumber(ln.num)
		}
	}
	return nil
}

// DeleteByHandle removes the rule whose synthetic handle matches. It re-lists,
// recomputes each managed rule's handle, and deletes the match by its CURRENT
// number — robust against UFW's number shifting. A miss is not an error.
func (u *UfwBackend) DeleteByHandle(handle int64) error {
	lines, err := u.listManagedLines()
	if err != nil {
		return err
	}
	for _, ln := range lines {
		if ln.r.Handle == handle {
			return u.deleteNumber(ln.num)
		}
	}
	return nil
}

// deleteNumber removes one rule by its current ufw number. `--force` skips the
// interactive confirmation `ufw delete` would otherwise require.
func (u *UfwBackend) deleteNumber(num int) error {
	_, err := u.run("--force", "delete", strconv.Itoa(num))
	return err
}

// ListUserRules returns every managed rule whose comment starts
// "<prefix>:<user>:" in one `ufw status numbered` pass.
func (u *UfwBackend) ListUserRules(user string) ([]Rule, error) {
	lines, err := u.listManagedLines()
	if err != nil {
		return nil, err
	}
	want := u.cfg.Prefix + ":" + user + ":"
	var out []Rule
	for _, ln := range lines {
		if strings.HasPrefix(ln.r.Comment, want) {
			out = append(out, ln.r)
		}
	}
	return out, nil
}

// ListManaged returns every managed rule whose comment starts "<prefix>:".
func (u *UfwBackend) ListManaged() ([]Rule, error) {
	lines, err := u.listManagedLines()
	if err != nil {
		return nil, err
	}
	out := make([]Rule, 0, len(lines))
	for _, ln := range lines {
		out = append(out, ln.r)
	}
	return out, nil
}

// ufwLine pairs a parsed managed Rule with its CURRENT ufw rule number (needed
// for deletion, kept out of the backend-neutral Rule).
type ufwLine struct {
	num int
	r   Rule
}

// listManagedLines runs `ufw status numbered` and parses the managed rules.
func (u *UfwBackend) listManagedLines() ([]ufwLine, error) {
	out, err := u.run("status", "numbered")
	if err != nil {
		return nil, err
	}
	return parseUfwStatus(u.cfg.Prefix, out), nil
}

var (
	// "[ 12] <body>" — the numbered-rule line shape.
	ufwNumRe = regexp.MustCompile(`^\s*\[\s*(\d+)\s*\]\s+(.*\S)\s*$`)
	// "<port>/<proto> [(v6)] ALLOW IN <ip>" within the body (comment stripped).
	ufwBodyRe = regexp.MustCompile(`^(\d+)/(\w+)(?:\s+\(v6\))?\s+ALLOW\s+IN\s+(\S+)`)
)

// parseUfwStatus extracts the nft-okboy-managed rules from `ufw status numbered`
// output. It keeps only rules whose comment starts "<prefix>:"; anything that
// does not match the expected shape is skipped (tolerant, like the nft parser).
// Each rule gets a stable synthetic Handle derived from its identity.
func parseUfwStatus(prefix, output string) []ufwLine {
	var lines []ufwLine
	for _, raw := range strings.Split(output, "\n") {
		m := ufwNumRe.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		num, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		body := m[2]
		// Split off the trailing "# comment".
		comment := ""
		if i := strings.IndexByte(body, '#'); i >= 0 {
			comment = strings.TrimSpace(body[i+1:])
			body = strings.TrimRight(body[:i], " \t")
		}
		if !strings.HasPrefix(comment, prefix+":") {
			continue // not one of ours
		}
		bm := ufwBodyRe.FindStringSubmatch(body)
		if bm == nil {
			continue // unexpected shape — skip rather than fail the whole list
		}
		port, err := strconv.Atoi(bm[1])
		if err != nil {
			continue
		}
		proto, ip := bm[2], bm[3]
		user, group := splitComment(prefix, comment)
		lines = append(lines, ufwLine{
			num: num,
			r: Rule{
				Handle:  synthHandle(comment, ip, port, proto),
				IP:      ip,
				Port:    port,
				Proto:   proto,
				User:    user,
				Group:   group,
				Comment: comment,
			},
		})
	}
	return lines
}

// synthHandle derives a stable, positive 64-bit handle from a rule's identity.
// Same identity => same handle on every List, so DeleteByHandle can locate the
// rule by re-listing even though UFW numbers shift. Collisions across a single
// host's small managed set are astronomically unlikely with FNV-1a.
func synthHandle(comment, ip string, port int, proto string) int64 {
	h := fnv.New64a()
	fmt.Fprintf(h, "%s|%s|%d|%s", comment, ip, port, proto)
	return int64(h.Sum64() & 0x7fffffffffffffff)
}
