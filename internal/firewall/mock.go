package firewall

import (
	"strings"
	"sync"
)

// Compile-time guarantee the mock stays a complete FirewallBackend.
var _ FirewallBackend = (*MockBackend)(nil)

// MockBackend is an in-memory FirewallBackend for unit tests on hosts without
// nftables (i.e. every non-Linux dev box). It reproduces the EXACT semantics the
// Manager relies on from the real backend: comment-keyed precise deletion, the
// single-pass ListUserRules prefix scan, and handle-based deletion. Nothing here
// shells out, so manager_test.go runs anywhere.
type MockBackend struct {
	mu     sync.Mutex
	prefix string
	next   int64    // monotonically increasing handle counter
	rules  []Rule   // the live rule set
	Calls  []string // ordered op log (e.g. "AddRule web 1.2.3.4:8080/tcp") — test introspection
}

// NewMockBackend returns an empty in-memory backend keyed to prefix.
func NewMockBackend(prefix string) *MockBackend {
	return &MockBackend{prefix: prefix, next: 1}
}

// EnsureBase is a no-op for the mock (no table/chain to create).
func (m *MockBackend) EnsureBase() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = append(m.Calls, "EnsureBase")
	return nil
}

// AddRule appends a rule with the production comment "<prefix>:<user>:<group>".
// The handle is auto-assigned, mirroring how nftables hands one back on insert.
func (m *MockBackend) AddRule(ip string, port int, user, proto, group string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := Rule{
		Handle:  m.next,
		IP:      ip,
		Port:    port,
		Proto:   proto,
		User:    user,
		Group:   group,
		Comment: commentFor(m.prefix, user, group),
	}
	m.next++
	m.rules = append(m.rules, r)
	m.Calls = append(m.Calls, "AddRule "+group+" "+endpoint(ip, port, proto))
	return nil
}

// RemoveRule deletes the rule matching ip+port+proto AND the exact comment for
// (user, group) — the precise, cross-group-safe delete from ufw_ops.remove_rule.
// Missing rules are silently ignored (the Python version logs a warning only).
func (m *MockBackend) RemoveRule(ip string, port int, user, proto, group string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := commentFor(m.prefix, user, group)
	for i, r := range m.rules {
		if r.IP == ip && r.Port == port && r.Proto == proto && r.Comment == want {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			m.Calls = append(m.Calls, "RemoveRule "+group+" "+endpoint(ip, port, proto))
			return nil
		}
	}
	m.Calls = append(m.Calls, "RemoveRule(miss) "+group+" "+endpoint(ip, port, proto))
	return nil
}

// ListUserRules returns every rule whose comment starts "<prefix>:<user>:" in one
// pass (the N+1-avoiding scan reconcile depends on).
func (m *MockBackend) ListUserRules(user string) ([]Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := m.prefix + ":" + user + ":"
	var out []Rule
	for _, r := range m.rules {
		if strings.HasPrefix(r.Comment, want) {
			out = append(out, r)
		}
	}
	m.Calls = append(m.Calls, "ListUserRules "+user)
	return out, nil
}

// DeleteByHandle removes the rule with the given handle (no-op if absent).
func (m *MockBackend) DeleteByHandle(handle int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, r := range m.rules {
		if r.Handle == handle {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			m.Calls = append(m.Calls, "DeleteByHandle "+itoa(handle))
			return nil
		}
	}
	m.Calls = append(m.Calls, "DeleteByHandle(miss) "+itoa(handle))
	return nil
}

// ListManaged returns every rule whose comment starts "<prefix>:".
func (m *MockBackend) ListManaged() ([]Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := m.prefix + ":"
	var out []Rule
	for _, r := range m.rules {
		if strings.HasPrefix(r.Comment, want) {
			out = append(out, r)
		}
	}
	return out, nil
}
