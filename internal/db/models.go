package db

// User mirrors a row of the users table (v2-v4 columns inline).
type User struct {
	ID              int64
	Username        string
	Secret          string
	IsAdmin         bool
	CurrentIP       *string // nullable
	LastKnock       *int64  // nullable unix seconds
	TOTPSecret      *string // v2
	TOTPEnabled     bool    // v2
	TOTPLastCounter int64   // v3 (replay protection)
	CreatedAt       string
}

// Group mirrors a row of the groups table.
type Group struct {
	ID        int64
	Name      string
	Port      int
	Proto     string
	CreatedAt string
}

// Membership mirrors a row of user_group_membership.
type Membership struct {
	UserID   int64
	GroupID  int64
	Enabled  bool
	JoinedAt string
}

// AuditEntry mirrors a row of audit_log.
type AuditEntry struct {
	ID        int64
	Actor     string
	Action    string
	Target    *string
	Detail    *string
	CreatedAt string
}

// GroupPort is a (group, port, proto) projection used by the firewall layer for
// reconcile / cleanup (mirrors the Python get_all_user_group_ports tuples).
type GroupPort struct {
	Group string
	Port  int
	Proto string
}

// UserGroupState powers the admin per-user group panel: every group plus this
// user's membership flags (mirrors admin_user_groups()).
type UserGroupState struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Proto    string `json:"proto"`
	IsMember bool   `json:"is_member"`
	Enabled  bool   `json:"enabled"`
}

// Node mirrors a row of the nodes table — a registered edge host whose agent
// pulls its desired firewall state from the hub. TokenHash is sha256(token); the
// raw token is shown once at creation and never stored.
type Node struct {
	ID        int64
	Name      string
	TokenHash string
	LastSeen  *int64 // nullable unix seconds (agent last contact)
	CreatedAt string
}

// GroupTarget mirrors a row of group_targets: a group's (port, proto) on a
// specific node. A group with no targets is local-only (legacy behavior); each
// target adds a remote node where the group's members get an allow rule.
type GroupTarget struct {
	ID      int64
	GroupID int64
	NodeID  int64
	Port    int
	Proto   string
}

// GroupTargetView is a GroupTarget joined with its group + node names, for listing.
type GroupTargetView struct {
	Group string
	Node  string
	Port  int
	Proto string
}

// DesiredRule is one allow rule an agent must enforce: the user's current IP may
// reach (Port, Proto). User+Group build the okboy comment so the agent's
// reconcile keys on the same identity the firewall backends use.
type DesiredRule struct {
	IP    string
	Port  int
	Proto string
	User  string
	Group string
}
