package firewall

// NoneBackend is a no-op FirewallBackend for a control-plane-only hub: it manages
// no local firewall — enforcement is delegated entirely to edge agents. Every
// method succeeds without touching anything, so a hub configured with
// `firewall_backend: none` records knocks and serves per-node desired state while
// never opening a local port itself.
type NoneBackend struct{}

var _ FirewallBackend = NoneBackend{}

func (NoneBackend) EnsureBase() error                                    { return nil }
func (NoneBackend) AddRule(string, int, string, string, string) error    { return nil }
func (NoneBackend) RemoveRule(string, int, string, string, string) error { return nil }
func (NoneBackend) ListUserRules(string) ([]Rule, error)                 { return nil, nil }
func (NoneBackend) DeleteByHandle(int64) error                           { return nil }
func (NoneBackend) ListManaged() ([]Rule, error)                         { return nil, nil }
