//go:build linux

package cli

import (
	"nft-okboy-fleet/internal/config"
	"nft-okboy-fleet/internal/firewall"
)

// newBackend builds the production nftables backend on Linux. It is wired from
// the config's nft_* knobs (table/chain/priority) and the shared rule prefix.
// EnsureBase is the caller's responsibility (serve calls it; the management
// commands tolerate its absence on a host that is not the firewall itself).
func newBackend(cfg *config.Config) (firewall.FirewallBackend, error) {
	switch cfg.FirewallBackend {
	case "none":
		return firewall.NoneBackend{}, nil
	case "ufw":
		return firewall.NewUfwBackend(firewall.UfwConfig{Prefix: cfg.RulePrefix})
	}
	return firewall.NewNftBackend(firewall.NftConfig{
		Prefix:   cfg.RulePrefix,
		Table:    cfg.NftTable,
		Chain:    cfg.NftChain,
		Priority: cfg.NftPriority,
	})
}
