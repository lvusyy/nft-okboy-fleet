// Package agent is the lightweight edge enforcer (milestone C3).
//
// Responsibilities (see ../../ROADMAP.md):
//   - Outbound-only long-poll to the hub (NAT/proxy friendly); never listens
//   - Reconcile the local firewall to the hub's desired state via
//     firewall.Backend (reuses the C1 backend abstraction)
//   - Stateless: managed rules are self-describing via the "nft-okboy:" comment
//     prefix; no local DB
//   - Fail-safe: on hub-unreachable keep last-known-good (never panic-close,
//     never auto-open); enforce a local max-ports allowlist as a guard against
//     a compromised hub
package agent
