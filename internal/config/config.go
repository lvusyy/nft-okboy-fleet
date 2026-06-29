// Package config loads and validates the YAML server configuration. The shape
// mirrors the Python config.example.yaml so existing operator configs port over
// with minimal change; defaults match the Python load_config() behavior.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// UserSeed is a first-run user entry under the `users:` map (one-time seed into
// the DB on a fresh install, mirroring the legacy config-dict bootstrap).
type UserSeed struct {
	Secret string `yaml:"secret"`
}

// Config is the full server configuration.
type Config struct {
	// Network / firewall
	ProtectedPorts []int  `yaml:"protected_ports"`
	AllowedPorts   []int  `yaml:"allowed_ports"` // optional whitelist for new group ports
	Proto          string `yaml:"proto"`
	ListenHost     string `yaml:"listen_host"`
	ListenPort     int    `yaml:"listen_port"`

	// Security
	SignatureTTL         int      `yaml:"signature_ttl"`
	RulePrefix           string   `yaml:"rule_prefix"`
	TrustedProxies       []string `yaml:"trusted_proxies"`
	ThrottleMaxFailures  int      `yaml:"throttle_max_failures"`
	ThrottleWindow       int      `yaml:"throttle_window"`
	RequireAdminTOTP     bool     `yaml:"require_admin_totp"`
	TOTPReplayProtection bool     `yaml:"totp_replay_protection"`

	// Anomaly detection
	AnomalyWindow     int `yaml:"anomaly_window"`
	AnomalyMaxChanges int `yaml:"anomaly_max_changes"`

	// Storage
	DBPath     string `yaml:"db_path"`
	BackupDir  string `yaml:"backup_dir"`
	BackupKeep int    `yaml:"backup_keep"`

	// Firewall backend: "nftables" (default) or "ufw".
	FirewallBackend string `yaml:"firewall_backend"`

	// nftables backend
	NftTable    string `yaml:"nft_table"`
	NftChain    string `yaml:"nft_chain"`
	NftPriority int    `yaml:"nft_priority"`

	// First-run user seed
	Users map[string]UserSeed `yaml:"users"`
}

// Load reads and parses the config file, applying defaults for any unset key.
//
// Defaults are pre-populated on the struct BEFORE unmarshalling: yaml.v3 only
// overwrites fields that actually appear in the document and leaves the rest
// untouched, so an omitted `totp_replay_protection` correctly stays true (the
// secure default) rather than collapsing to Go's false zero-value.
func Load(path string) (*Config, error) {
	c := &Config{
		Proto:                "tcp",
		ListenHost:           "127.0.0.1",
		ListenPort:           5000,
		SignatureTTL:         300,
		RulePrefix:           "okboy",
		TrustedProxies:       []string{"127.0.0.1", "::1"},
		ThrottleMaxFailures:  10,
		ThrottleWindow:       300,
		RequireAdminTOTP:     false,
		TOTPReplayProtection: true,
		AnomalyWindow:        3600,
		AnomalyMaxChanges:    5,
		DBPath:               "/var/lib/okboy/okboy.db",
		BackupDir:            "/var/lib/okboy/backups",
		BackupKeep:           7,
		FirewallBackend:      "nftables",
		NftTable:             "okboy",
		NftChain:             "input",
		NftPriority:          -150,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if c.Proto == "" {
		c.Proto = "tcp"
	}
	if c.RulePrefix == "" {
		c.RulePrefix = "okboy"
	}
	if c.FirewallBackend == "" {
		c.FirewallBackend = "nftables"
	}
	switch c.FirewallBackend {
	case "nftables", "ufw", "none":
	default:
		return nil, fmt.Errorf("parse config %q: firewall_backend must be %q, %q or %q, got %q",
			path, "nftables", "ufw", "none", c.FirewallBackend)
	}
	return c, nil
}
