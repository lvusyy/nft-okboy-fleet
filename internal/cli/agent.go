package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nft-okboy-fleet/internal/agent"
	"nft-okboy-fleet/internal/config"
)

// CmdAgent runs okboy as an edge agent: it pulls this node's desired firewall
// state from the hub and reconciles the local firewall to it on every interval,
// until SIGINT/SIGTERM. It needs a config only for the firewall backend
// (firewall_backend / rule_prefix / nft_*) — there is NO local database.
func CmdAgent(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	hub := fs.String("hub", "", "Hub base URL, e.g. https://hub.example/")
	token := fs.String("token", "", "Node enrollment token (from `node-add`)")
	node := fs.String("node", "", "Node name (for logging)")
	interval := fs.Int("interval", 15, "Pull interval in seconds")
	insecure := fs.Bool("insecure", false, "Skip TLS verification (self-signed hub cert)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *hub == "" || *token == "" {
		return fmt.Errorf("usage: agent --hub <url> --token <token> [--node <name>] [--interval 15] [--insecure]")
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("agent needs a config for the firewall backend (firewall_backend/rule_prefix): %w", err)
	}
	be, err := newBackend(cfg)
	if err != nil {
		return fmt.Errorf("firewall backend init failed: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return agent.Run(ctx, be, agent.Options{
		HubURL:   *hub,
		Token:    *token,
		NodeName: *node,
		Interval: time.Duration(*interval) * time.Second,
		Insecure: *insecure,
	})
}
