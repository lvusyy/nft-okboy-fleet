// Command nft-okboy is the nft-okboy server + management CLI — a faithful Go port of
// the Python server/app.py argparse dispatch. main stays intentionally thin: it
// resolves the global -c/--config flag, peels off the subcommand, and hands the
// remaining args to the matching handler in internal/cli. All real logic lives in
// the cli package.
package main

import (
	"fmt"
	"os"

	"nft-okboy-fleet/internal/cli"
)

// version is injected at build time via:
//
//	go build -ldflags "-X main.version=$(cat VERSION)"
//
// It defaults to "dev" because //go:embed cannot reach ../../VERSION across the
// module boundary; the release build sets the real value.
var version = "dev"

// defaultConfigPath is the fallback config location when -c/--config is omitted
// and no config.yaml sits next to the executable (mirrors the Python
// script-relative default, but for a packaged install).
const defaultConfigPath = "/etc/nft-okboy/config.yaml"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// run parses the global flags + subcommand and dispatches. Returning an error
// (rather than exiting inline) keeps the dispatch table boring and testable.
func run(argv []string) error {
	cfgPath, cmd, rest := parseGlobal(argv)

	switch cmd {
	case "", "-h", "--help", "help":
		usage()
		return nil
	case "-V", "--version", "version":
		fmt.Printf("nft-okboy %s\n", version)
		return nil
	case "serve":
		return cli.CmdServe(cfgPath, version, rest)
	case "gen-secret":
		return cli.CmdGenSecret(rest)
	case "user-add":
		return cli.CmdUserAdd(cfgPath, rest)
	case "user-del":
		return cli.CmdUserDel(cfgPath, rest)
	case "user-list":
		return cli.CmdUserList(cfgPath, rest)
	case "group-add":
		return cli.CmdGroupAdd(cfgPath, rest)
	case "group-del":
		return cli.CmdGroupDel(cfgPath, rest)
	case "group-list":
		return cli.CmdGroupList(cfgPath, rest)
	case "node-add":
		return cli.CmdNodeAdd(cfgPath, rest)
	case "node-list":
		return cli.CmdNodeList(cfgPath, rest)
	case "node-del":
		return cli.CmdNodeDel(cfgPath, rest)
	case "group-target":
		return cli.CmdGroupTarget(cfgPath, rest)
	case "agent":
		return cli.CmdAgent(cfgPath, version, rest)
	case "user-join":
		return cli.CmdUserJoin(cfgPath, rest)
	case "user-leave":
		return cli.CmdUserLeave(cfgPath, rest)
	case "admin-add":
		return cli.CmdAdminAdd(cfgPath, rest)
	case "revoke":
		return cli.CmdRevoke(cfgPath, rest)
	case "list":
		return cli.CmdList(cfgPath, rest)
	case "cleanup":
		return cli.CmdCleanup(cfgPath, rest)
	case "backup":
		return cli.CmdBackup(cfgPath, rest)
	case "totp-uri":
		return cli.CmdTOTPURI(cfgPath, rest)
	case "upgrade":
		return cli.CmdUpgrade(cfgPath, version, rest)
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// parseGlobal extracts a leading/embedded global -c/--config flag, then returns
// the resolved config path, the subcommand, and the args that follow it.
//
// The flag is accepted either before the subcommand ("nft-okboy -c x serve") or the
// scan stops at the first non-flag token, which becomes the subcommand; remaining
// tokens are forwarded verbatim so each subcommand can run its own FlagSet
// (sub-flags like --admin/--proto are parsed there, not here).
func parseGlobal(argv []string) (cfgPath, cmd string, rest []string) {
	cfgPath = resolveDefaultConfig()
	i := 0
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "-c" || a == "--config":
			if i+1 < len(argv) {
				cfgPath = argv[i+1]
				i += 2
				continue
			}
			i++ // dangling flag — ignore, the subcommand will report the miss
		case len(a) > 3 && a[:3] == "-c=":
			cfgPath = a[3:]
			i++
		case len(a) > 9 && a[:9] == "--config=":
			cfgPath = a[9:]
			i++
		default:
			// First non-(global-flag) token is the subcommand.
			return cfgPath, a, argv[i+1:]
		}
	}
	return cfgPath, "", nil
}

// resolveDefaultConfig mirrors the Python "config next to the script" fix: prefer
// a config.yaml beside the executable, else fall back to the system path. The
// explicit -c flag (handled in parseGlobal) always wins over both.
func resolveDefaultConfig() string {
	if exe, err := os.Executable(); err == nil {
		beside := dir(exe) + string(os.PathSeparator) + "config.yaml"
		if st, err := os.Stat(beside); err == nil && !st.IsDir() {
			return beside
		}
	}
	return defaultConfigPath
}

// dir returns the directory portion of a path (avoids importing path/filepath for
// one call in this tiny main; the cli package uses filepath where it matters).
func dir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[:i]
		}
	}
	return "."
}

func usage() {
	fmt.Fprint(os.Stderr, `nft-okboy - nftables dynamic firewall allowlist manager

Usage:
  nft-okboy [-c <config>] <command> [args]

Global flags:
  -c, --config <path>   Config file (default: config.yaml beside the binary, else `+defaultConfigPath+`)
  -V, --version         Print version and exit

Commands:
  serve [--debug]                 Start the API server (hub / standalone)
  agent --hub <url> --token <tok> [--node <name>] [--interval 15] [--insecure]
                                  Run as an edge agent (pull desired state, apply locally)
  gen-secret [username]           Generate a fresh user secret
  user-add <name> [--admin]       Create a user (prints the secret)
  user-del <name>                 Delete a user + clean firewall rules
  user-list                       List users
  group-add <name> <port> [--proto tcp]
                                  Create a port group
  group-del <name>                Delete a group + clean firewall rules
  group-list                      List groups
  node-add <name>                 Register an edge node (prints its token once)
  node-list                       List registered nodes + last-seen
  node-del <name>                 Delete a node + its group targets
  group-target add <group> <node> <port> [--proto tcp]
                                  Map a group to a node's port (hub desired state)
  group-target list               List group->node port targets
  group-target del <group> <node> Remove a group->node target
  user-join <user> <group>        Add user to a group
  user-leave <user> <group>       Remove user from a group
  admin-add <user>                Grant admin privileges
  revoke <user> [--no-rotate]     Close ports, clear state, rotate secret
  list                            List managed firewall rules
  cleanup [--max-age <days>]      Remove stale rules (default age: 7 days)
  backup                          Checksummed DB backup (rolling retention)
  totp-uri <user>                 Print an otpauth:// URI for a user's TOTP secret
  upgrade [--check] [--version vX.Y.Z]
                                  Self-update to the latest release (backs up the
                                  DB, verifies sha256, restarts the service)
  version                         Print version and exit
`)
}
