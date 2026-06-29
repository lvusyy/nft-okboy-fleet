// Package hub is the centralized control plane (milestone C2).
//
// Responsibilities (see ../../ROADMAP.md):
//   - Node registry + enrollment (one-time token -> per-node mTLS cert)
//   - Per-node desired-state computation from users/groups/membership
//   - Long-poll endpoint serving each node its signed desired ruleset
//   - knock fan-out (C4): one client knock -> desired state across the fleet
//
// The hub never touches a firewall; it only computes intent. Enforcement
// lives in package agent.
package hub
