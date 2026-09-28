package firewall

// ReconcileAll makes the backend's managed rule set EXACTLY match desired — the
// whole-host counterpart of Manager.Reconcile (which handles one user): add every
// desired rule that is missing, then delete every managed rule no longer desired,
// keyed on (ip, port, proto, user, group). A second copy of a desired rule (two
// adds that raced) is deleted as well, so the set converges to one rule per key.
// Idempotent — a second call with the same desired set issues no mutations. A
// per-rule backend error is collected (not fatal) so one bad rule cannot block
// the rest; the last one is returned.
func ReconcileAll(be FirewallBackend, desired []Rule) (added, removed int, err error) {
	managed, lerr := be.ListManaged()
	if lerr != nil {
		return 0, 0, lerr
	}
	type key struct {
		ip, proto, user, group string
		port                   int
	}
	want := make(map[key]bool, len(desired))
	for _, d := range desired {
		want[key{d.IP, d.Proto, d.User, d.Group, d.Port}] = true
	}
	have := make(map[key]bool, len(managed))
	var extra []int64
	for _, m := range managed {
		k := key{m.IP, m.Proto, m.User, m.Group, m.Port}
		if want[k] && !have[k] {
			have[k] = true
			continue
		}
		extra = append(extra, m.Handle) // not desired, or a duplicate of a kept rule
	}
	// Add before deleting, so a rule being replaced never leaves a gap.
	for _, d := range desired {
		k := key{d.IP, d.Proto, d.User, d.Group, d.Port}
		if have[k] {
			continue
		}
		have[k] = true
		if e := be.AddRule(d.IP, d.Port, d.User, d.Proto, d.Group); e != nil {
			err = e
			continue
		}
		added++
	}
	for _, h := range extra {
		if e := be.DeleteByHandle(h); e != nil {
			err = e
			continue
		}
		removed++
	}
	return added, removed, err
}
