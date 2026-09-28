package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nft-okboy-fleet/internal/firewall"
)

// Options configures the agent loop.
type Options struct {
	HubURL   string         // hub base URL, e.g. https://hub.example/
	Token    string         // node enrollment token (bearer)
	NodeName string         // for logging only
	Interval time.Duration  // pull cadence
	Insecure bool           // skip TLS verification (self-signed hub cert) — prefer RootCAs
	RootCAs  *x509.CertPool // when set, the only trust store for the hub certificate (its CA, or the self-signed cert)
	Version  string         // agent binary version, self-reported to the hub (fleet view)
	Backend  string         // firewall backend name, self-reported to the hub
	// AllowedPorts is the node's local guard: when non-empty, the agent opens
	// ONLY these ports and refuses any hub-supplied rule on another port — so a
	// compromised hub still cannot tell this node to open, say, SSH. Empty = all.
	AllowedPorts []int
	// Guard (nft_guard) makes an nftables backend close the node's managed ports
	// to everyone its allow rules do not admit; false removes that guard. Only
	// ports listed in AllowedPorts are ever guarded: the hub reports which ports
	// the node manages, but must not be able to close arbitrary ones.
	Guard bool
	// StateFile keeps the last guard applied, so it is back at once after a
	// reboot or a flushed ruleset even while the hub cannot be asked ("" = off).
	StateFile string
}

// rule is one desired allow rule as served by the hub's node desired-state API.
type rule struct {
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	User  string `json:"user"`
	Group string `json:"group"`
}

type desiredResp struct {
	OK    bool   `json:"ok"`
	Node  string `json:"node"`
	Rules []rule `json:"rules"`
	// Ports are the node's managed ports (its group targets); nil when the hub
	// is older than this field.
	Ports *[]struct {
		Port  int    `json:"port"`
		Proto string `json:"proto"`
	} `json:"ports"`
}

// errRevoked: the hub rejected the node token — the node was deleted or its
// token replaced. Unlike a network or server error, that is an answer.
var errRevoked = errors.New("the hub rejected this node's token (node deleted or token replaced)")

// state is what the loop remembers between cycles.
type state struct {
	revoked, warnedNoPorts bool   // log a condition once
	unguarded              string // hub ports last reported as outside AllowedPorts
	// ports is the guard last applied (nil = none); havePorts says it is known
	// (applied in this run, or loaded from Options.StateFile); saved says the
	// state file holds it.
	ports            []firewall.PortProto
	havePorts, saved bool
}

// Run is the agent loop: pull the node's desired state from the hub, reconcile
// the local firewall to it, sleep, repeat — until ctx is cancelled. A pull
// failure is FAIL-SAFE: the current rules are left untouched (never flush the
// allowlist because the hub blipped), and the next tick retries. A rejected
// token is not a blip, though: see step.
func Run(ctx context.Context, be firewall.FirewallBackend, opts Options) error {
	if opts.Interval <= 0 {
		opts.Interval = 15 * time.Second
	}
	if err := be.EnsureBase(); err != nil {
		return fmt.Errorf("firewall base init: %w", err)
	}
	if opts.Insecure {
		log.Printf("agent: WARNING: --insecure — the hub certificate is NOT verified; anyone on the path can pose as the hub and steal the node token (pin it with --ca instead)")
	}
	client := newClient(opts)
	url := strings.TrimRight(opts.HubURL, "/") + "/api/v1/node/desired-state"
	log.Printf("agent: node=%q hub=%s interval=%s", opts.NodeName, url, opts.Interval)

	st := &state{}
	loadGuard(opts, st)
	for {
		step(ctx, be, client, url, opts, st)
		select {
		case <-ctx.Done():
			log.Printf("agent: stopping")
			return nil
		case <-time.After(opts.Interval):
		}
	}
}

// step is one agent cycle: re-ensure the firewall base, pull, reconcile, guard.
func step(ctx context.Context, be firewall.FirewallBackend, client *http.Client, url string, opts Options, st *state) {
	// Every cycle, not just at start: `systemctl restart nftables` flushes the
	// whole ruleset, nft-okboy's table included, and nothing else recreates it.
	if err := be.EnsureBase(); err != nil {
		log.Printf("agent: firewall base: %v", err)
		return
	}
	// Put the last guard back before asking the hub: a flush or reboot must not
	// leave the ports open while the pull is pending (up to its timeout) or fails.
	reapplyGuard(be, opts, st)
	dr, err := fetch(ctx, client, url, opts)
	if errors.Is(err, errRevoked) {
		// Fail closed: a node the hub no longer knows must not keep admitting
		// anyone. The guard stays, so its ports end up closed.
		// (A disabled ufw is reported once, like the revocation: the rules go
		// in the first cycle after it is enabled.)
		_, removed, rerr := Reconcile(be, nil)
		if !st.revoked || removed > 0 || (rerr != nil && !errors.Is(rerr, firewall.ErrInactive)) {
			log.Printf("agent: %v — removed %d managed rule(s)%s", err, removed, errSuffix(rerr))
		}
		st.revoked = true
		return
	}
	if err != nil {
		log.Printf("agent: pull failed, keeping current rules: %v", err)
		return
	}
	st.revoked = false
	desired := filterAllowed(sanitize(dr.Rules), opts.AllowedPorts)
	added, removed, rerr := Reconcile(be, desired)
	switch {
	case errors.Is(rerr, firewall.ErrInactive):
		// ufw is disabled: EnsureBase already warned; nothing changes until it is enabled.
	case rerr != nil:
		log.Printf("agent: reconcile error (partial): %v", rerr)
	case added > 0 || removed > 0:
		log.Printf("agent: reconciled (+%d/-%d rules, %d desired)", added, removed, len(desired))
	}
	syncGuard(be, dr, opts, st)
}

// syncGuard (nftables backend) closes the node's managed ports — the hub's
// "ports" that are also listed in AllowedPorts — to everyone the allow rules do
// not admit. Without AllowedPorts nothing is guarded: which ports get closed is
// the node's decision, so a compromised hub cannot close, say, SSH fleet-wide.
// A hub too old to send "ports" leaves the last guard in place.
func syncGuard(be firewall.FirewallBackend, dr *desiredResp, opts Options, st *state) {
	g, ok := be.(firewall.Guard)
	if !ok {
		return
	}
	var ports []firewall.PortProto
	if opts.Guard {
		if dr.Ports == nil {
			if !st.warnedNoPorts {
				st.warnedNoPorts = true
				log.Printf("agent: the hub does not report this node's ports (hub older than this agent): the nftables guard is left as is — upgrade the hub")
			}
			return
		}
		hub := make([]firewall.PortProto, 0, len(*dr.Ports))
		for _, p := range *dr.Ports {
			hub = append(hub, firewall.PortProto{Port: p.Port, Proto: p.Proto})
		}
		var skipped []firewall.PortProto
		ports, skipped = splitAllowed(hub, opts.AllowedPorts)
		if msg := portList(skipped); msg != st.unguarded {
			st.unguarded = msg
			if msg != "" {
				log.Printf("agent: the hub manages %s on this node, but agent_allowed_ports does not list it: nft-okboy neither opens nor closes it here (only listed ports are guarded, so a compromised hub cannot close arbitrary ports)", msg)
			}
		}
	}
	if err := g.SyncGuard(ports); err != nil {
		log.Printf("agent: guard: %v", err)
		return
	}
	saveGuard(opts, st, ports)
}

// splitAllowed separates the ports listed in allowed from the others (all of
// them are "others" when allowed is empty).
func splitAllowed(ports []firewall.PortProto, allowed []int) (in, out []firewall.PortProto) {
	ok := make(map[int]bool, len(allowed))
	for _, p := range allowed {
		ok[p] = true
	}
	for _, p := range ports {
		if ok[p.Port] {
			in = append(in, p)
		} else {
			out = append(out, p)
		}
	}
	return in, out
}

// portList renders ports as "22/tcp, 53/udp" ("" for none).
func portList(ports []firewall.PortProto) string {
	s := make([]string, 0, len(ports))
	for _, p := range ports {
		s = append(s, fmt.Sprintf("%d/%s", p.Port, p.Proto))
	}
	return strings.Join(s, ", ")
}

// reapplyGuard puts the last known guard back (SyncGuard is a no-op when it is
// still in place). step calls it every cycle before the pull, so a flushed or
// rebooted firewall is guarded again at once, whatever the hub answers — and
// however long it takes to. The current config still rules: nft_guard off, or a
// port no longer listed in AllowedPorts, is honoured before the hub answers.
func reapplyGuard(be firewall.FirewallBackend, opts Options, st *state) {
	g, ok := be.(firewall.Guard)
	if !ok || !st.havePorts {
		return
	}
	var ports []firewall.PortProto
	if opts.Guard {
		ports, _ = splitAllowed(st.ports, opts.AllowedPorts)
	}
	if err := g.SyncGuard(ports); err != nil {
		log.Printf("agent: guard: %v", err)
	}
}

// loadGuard reads the guard saved by a previous run (none on the first run).
func loadGuard(opts Options, st *state) {
	if opts.StateFile == "" {
		return
	}
	b, err := os.ReadFile(opts.StateFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("agent: guard state: %v", err)
		}
		return
	}
	var ports []firewall.PortProto
	if err := json.Unmarshal(b, &ports); err != nil {
		log.Printf("agent: guard state %s: %v", opts.StateFile, err)
		return
	}
	st.ports, st.havePorts, st.saved = ports, true, true
}

// saveGuard remembers ports as the applied guard and writes it to
// Options.StateFile unless the file already holds it — so a failed write is
// retried on the next cycle.
func saveGuard(opts Options, st *state, ports []firewall.PortProto) {
	if !st.havePorts || !samePorts(st.ports, ports) {
		st.ports, st.havePorts, st.saved = ports, true, false
	}
	if opts.StateFile == "" || st.saved {
		return
	}
	if err := writeState(opts.StateFile, ports); err != nil {
		log.Printf("agent: guard state (retried next cycle): %v", err)
		return
	}
	st.saved = true
}

// writeState stores ports atomically: a synced temp file renamed over the old.
func writeState(path string, ports []firewall.PortProto) error {
	b, err := json.Marshal(ports)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func samePorts(a, b []firewall.PortProto) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func errSuffix(err error) string {
	if err == nil {
		return ""
	}
	return " (errors: " + err.Error() + ")"
}

// newClient builds the hub client: TLS verified against the system roots, or
// against opts.RootCAs only when set (a pinned CA / self-signed hub cert), or not
// at all with opts.Insecure.
func newClient(opts Options) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	switch {
	case opts.Insecure:
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	case opts.RootCAs != nil:
		transport.TLSClientConfig = &tls.Config{RootCAs: opts.RootCAs}
	}
	return &http.Client{
		Timeout:   opts.Interval + 10*time.Second,
		Transport: transport,
		// Never follow a redirect: the bearer token goes to the configured hub URL
		// only, and a redirect could lead it elsewhere or down to plain http.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// fetch GETs the node desired-state with the bearer token and decodes it. A 401
// is errRevoked.
func fetch(ctx context.Context, client *http.Client, url string, opts Options) (*desiredResp, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+opts.Token)
	if opts.Version != "" {
		req.Header.Set("X-Nft-Okboy-Version", opts.Version)
	}
	if opts.Backend != "" {
		req.Header.Set("X-Nft-Okboy-Backend", opts.Backend)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errRevoked
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hub returned HTTP %d", resp.StatusCode)
	}
	var dr desiredResp
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, fmt.Errorf("decode desired state: %w", err)
	}
	if !dr.OK {
		return nil, fmt.Errorf("hub responded ok=false")
	}
	return &dr, nil
}

// Reconcile makes the backend's managed rule set EXACTLY match desired (see
// firewall.ReconcileAll, which the hub uses for its own firewall too): add every
// missing desired rule, delete every managed rule no longer desired or
// duplicated. Idempotent; per-rule backend errors are collected, not fatal.
func Reconcile(be firewall.FirewallBackend, desired []rule) (added, removed int, err error) {
	rules := make([]firewall.Rule, 0, len(desired))
	for _, d := range desired {
		rules = append(rules, firewall.Rule{IP: d.IP, Port: d.Port, Proto: d.Proto, User: d.User, Group: d.Group})
	}
	return firewall.ReconcileAll(be, rules)
}

// sanitize drops every hub rule that is not one IP address on a valid port and
// protocol for well-formed user/group names, and canonicalizes the IP so it
// compares equal to what the firewall lists back. A compromised hub must not be
// able to smuggle "any" or a CIDR into a rule (ufw reads both as "everyone").
func sanitize(desired []rule) []rule {
	var out []rule
	for _, d := range desired {
		ip := firewall.CanonicalIP(d.IP)
		if ip == "" || d.Port < 1 || d.Port > 65535 || (d.Proto != "tcp" && d.Proto != "udp") ||
			!firewall.ValidName(d.User) || !firewall.ValidName(d.Group) {
			log.Printf("agent: REFUSED malformed hub rule ip=%q port=%d proto=%q user=%q group=%q — possible hostile hub",
				d.IP, d.Port, d.Proto, d.User, d.Group)
			continue
		}
		d.IP = ip
		out = append(out, d)
	}
	return out
}

// filterAllowed drops every desired rule whose port is not in allowed — the
// node's local guard against a compromised/hostile hub. allowed empty => no
// filtering (return desired unchanged). Each distinct refused port is logged
// once per cycle so an attempt to push a forbidden port (e.g. SSH) is visible.
func filterAllowed(desired []rule, allowed []int) []rule {
	if len(allowed) == 0 {
		return desired
	}
	ok := make(map[int]bool, len(allowed))
	for _, p := range allowed {
		ok[p] = true
	}
	var out []rule
	logged := map[int]bool{}
	for _, d := range desired {
		if ok[d.Port] {
			out = append(out, d)
			continue
		}
		if !logged[d.Port] {
			logged[d.Port] = true
			log.Printf("agent: REFUSED hub rule on port %d (not in agent_allowed_ports) — possible hostile hub", d.Port)
		}
	}
	return out
}
