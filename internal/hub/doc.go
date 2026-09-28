// Package hub contains no code; it documents where the fleet control plane
// lives.
//
// The hub is an ordinary "nft-okboy serve" whose database also holds edge nodes
// and group targets:
//   - internal/db (nodes.go): the nodes and group_targets tables, node tokens
//     (only their SHA-256 is stored), and DesiredStateForNode, which projects
//     users, enabled memberships and group targets onto one node's allow rules;
//   - internal/server (node.go): GET /api/v1/node/desired-state, which
//     authenticates an agent by its bearer token and returns that node's rules
//     and managed ports, and GET /api/admin/nodes, the fleet view;
//   - internal/cli (node.go): node-add, node-list, node-del and group-target.
//
// Nothing is pushed to the nodes: a knock records the user's current IP, and
// each agent picks up the change on its next pull. With firewall_backend: none
// the hub manages no local firewall; with nftables or ufw it also enforces each
// group's own port on the hub host. Enforcement on edge nodes lives in package
// agent.
package hub
