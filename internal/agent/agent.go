package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"nft-okboy-fleet/internal/firewall"
)

// Options configures the agent loop.
type Options struct {
	HubURL   string        // hub base URL, e.g. https://hub.example/
	Token    string        // node enrollment token (bearer)
	NodeName string        // for logging only
	Interval time.Duration // pull cadence
	Insecure bool          // skip TLS verification (self-signed hub cert)
	Version  string        // agent binary version, self-reported to the hub (fleet view)
	Backend  string        // firewall backend name, self-reported to the hub
	// AllowedPorts is the node's local guard: when non-empty, the agent opens
	// ONLY these ports and refuses any hub-supplied rule on another port — so a
	// compromised hub still cannot tell this node to open, say, SSH. Empty = all.
	AllowedPorts []int
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
}

// Run is the agent loop: pull the node's desired state from the hub, reconcile
// the local firewall to it, sleep, repeat — until ctx is cancelled. A pull
// failure is FAIL-SAFE: the current rules are left untouched (never flush the
// allowlist because the hub blipped), and the next tick retries.
func Run(ctx context.Context, be firewall.FirewallBackend, opts Options) error {
	if opts.Interval <= 0 {
		opts.Interval = 15 * time.Second
	}
	if err := be.EnsureBase(); err != nil {
		return fmt.Errorf("firewall base init: %w", err)
	}
	client := &http.Client{Timeout: opts.Interval + 10*time.Second}
	if opts.Insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	url := strings.TrimRight(opts.HubURL, "/") + "/api/v1/node/desired-state"
	log.Printf("agent: node=%q hub=%s interval=%s", opts.NodeName, url, opts.Interval)

	for {
		if desired, err := fetch(ctx, client, url, opts); err != nil {
			log.Printf("agent: pull failed, keeping current rules: %v", err)
		} else {
			desired = filterAllowed(desired, opts.AllowedPorts)
			added, removed, rerr := Reconcile(be, desired)
			switch {
			case rerr != nil:
				log.Printf("agent: reconcile error (partial): %v", rerr)
			case added > 0 || removed > 0:
				log.Printf("agent: reconciled (+%d/-%d rules, %d desired)", added, removed, len(desired))
			}
		}
		select {
		case <-ctx.Done():
			log.Printf("agent: stopping")
			return nil
		case <-time.After(opts.Interval):
		}
	}
}

// fetch GETs the node desired-state with the bearer token and decodes the rules.
func fetch(ctx context.Context, client *http.Client, url string, opts Options) ([]rule, error) {
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
	return dr.Rules, nil
}

// Reconcile makes the backend's managed rule set EXACTLY match desired: add every
// desired rule that is missing, delete every managed rule no longer desired, keyed
// on (ip, port, proto, user, group). Idempotent — a second call with the same
// desired set issues no mutations. A per-rule backend error is collected (not
// fatal) so one bad rule cannot block the rest, mirroring Manager.Reconcile.
func Reconcile(be firewall.FirewallBackend, desired []rule) (added, removed int, err error) {
	managed, lerr := be.ListManaged()
	if lerr != nil {
		return 0, 0, lerr
	}
	type key struct {
		ip, proto, user, group string
		port                   int
	}
	want := make(map[key]bool, len(desired))
	for _, d := range desired {
		want[key{d.IP, d.Proto, d.User, d.Group, d.Port}] = true
	}
	have := make(map[key]firewall.Rule, len(managed))
	for _, m := range managed {
		have[key{m.IP, m.Proto, m.User, m.Group, m.Port}] = m
	}
	for _, d := range desired {
		k := key{d.IP, d.Proto, d.User, d.Group, d.Port}
		if _, ok := have[k]; ok {
			continue
		}
		if e := be.AddRule(d.IP, d.Port, d.User, d.Proto, d.Group); e != nil {
			err = e
			continue
		}
		added++
	}
	for k, m := range have {
		if want[k] {
			continue
		}
		if e := be.DeleteByHandle(m.Handle); e != nil {
			err = e
			continue
		}
		removed++
	}
	return added, removed, err
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
