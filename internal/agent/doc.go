// Package agent is the edge side of fleet mode ("nft-okboy agent").
//
// Every interval (15 seconds by default) Run:
//   - re-creates the firewall base (table and chain) and puts the last known
//     nftables guard back, so a flushed ruleset or a reboot is covered before
//     the hub answers;
//   - pulls GET /api/v1/node/desired-state from the hub with the node's bearer
//     token (the agent command in internal/cli accepts plain http only on
//     loopback or with --allow-http; redirects are never followed);
//   - drops malformed rules (anything but a single IP, a valid port and
//     protocol, and valid user and group names) and rules on ports missing
//     from agent_allowed_ports, then reconciles the managed rules to exactly
//     that set (firewall.ReconcileAll);
//   - with the nftables backend, guards the node's managed ports that are also
//     listed in agent_allowed_ports, and saves that guard to the state file.
//
// A failed pull leaves the current rules untouched. A 401 (node deleted or
// token replaced) removes every allow rule but keeps the guard, so guarded
// ports close. The agent keeps no database and listens on no port; its only
// local state is the guard file (--state).
package agent
