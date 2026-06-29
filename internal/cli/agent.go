package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nft-okboy-fleet/internal/agent"
	"nft-okboy-fleet/internal/config"
)

// CmdAgent runs okboy as an edge agent: it pulls this node's desired firewall
// state from the hub and reconciles the local firewall to it on every interval,
// until SIGINT/SIGTERM. It needs a config only for the firewall backend
// (firewall_backend / rule_prefix / nft_* / agent_allowed_ports) — there is NO
// local database.
func CmdAgent(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	hub := fs.String("hub", "", "Hub base URL, e.g. https://hub.example/")
	token := fs.String("token", "", "Node enrollment token (from `node-add`)")
	node := fs.String("node", "", "Node name (for logging)")
	interval := fs.Int("interval", 15, "Pull interval in seconds")
	insecure := fs.Bool("insecure", false, "Skip TLS verification (self-signed hub cert)")
	allowPorts := fs.String("allow-ports", "", "Comma-separated ports this agent may open (overrides config agent_allowed_ports)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *hub == "" || *token == "" {
		return fmt.Errorf("usage: agent --hub <url> --token <token> [--node <name>] [--interval 15] [--insecure] [--allow-ports 18080,443]")
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("agent needs a config for the firewall backend (firewall_backend/rule_prefix): %w", err)
	}
	be, err := newBackend(cfg)
	if err != nil {
		return fmt.Errorf("firewall backend init failed: %w", err)
	}

	// The --allow-ports flag overrides agent_allowed_ports from the config.
	allowed := cfg.AgentAllowedPorts
	if *allowPorts != "" {
		allowed = nil
		for _, p := range strings.Split(*allowPorts, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			n, perr := strconv.Atoi(p)
			if perr != nil {
				return fmt.Errorf("--allow-ports: %q is not an integer", p)
			}
			allowed = append(allowed, n)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return agent.Run(ctx, be, agent.Options{
		HubURL:       *hub,
		Token:        *token,
		NodeName:     *node,
		Interval:     time.Duration(*interval) * time.Second,
		Insecure:     *insecure,
		AllowedPorts: allowed,
	})
}
