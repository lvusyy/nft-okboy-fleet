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
	// to everyone its allow rules do not admit; false removes that guard.
	Guard bool
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

// state is what the loop remembers between cycles (to log changes once).
type state struct {
	revoked, warnedNoPorts bool
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
	dr, err := fetch(ctx, client, url, opts)
	if errors.Is(err, errRevoked) {
		// Fail closed: a node the hub no longer knows must not keep admitting
		// anyone. The guard stays, so its ports end up closed.
		_, removed, rerr := Reconcile(be, nil)
		if !st.revoked || removed > 0 || rerr != nil {
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
	case rerr != nil:
		log.Printf("agent: reconcile error (partial): %v", rerr)
	case added > 0 || removed > 0:
		log.Printf("agent: reconciled (+%d/-%d rules, %d desired)", added, removed, len(desired))
	}
	syncGuard(be, dr, opts, st)
}

// syncGuard (nftables backend) closes the node's managed ports — the hub's
// "ports", narrowed to AllowedPorts when set, exactly like the allow rules — to
// everyone the allow rules do not admit. A hub too old to send "ports" leaves
// the guard as it is.
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
		allowed := make(map[int]bool, len(opts.AllowedPorts))
		for _, p := range opts.AllowedPorts {
			allowed[p] = true
		}
		for _, p := range *dr.Ports {
			if len(allowed) == 0 || allowed[p.Port] {
				ports = append(ports, firewall.PortProto{Port: p.Port, Proto: p.Proto})
			}
		}
	}
	if err := g.SyncGuard(ports); err != nil {
		log.Printf("agent: guard: %v", err)
	}
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
