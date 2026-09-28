package server

import (
	"errors"
	"log"
	"time"

	"nft-okboy-fleet/internal/firewall"
)

// MaintainEvery is how often serve runs Maintain.
const MaintainEvery = 30 * time.Second

// cleanupEvery is how often Maintain expires users who stopped knocking.
const cleanupEvery = time.Hour

// Maintain re-asserts this server's own firewall from the database. serve runs
// it at start and every MaintainEvery. Knocks keep each user's rules current,
// but nothing else would repair:
//   - a table/chain flushed from under us (`systemctl restart nftables` reloads
//     a ruleset that usually starts with `flush ruleset`);
//   - rules orphaned by a failed delete — a deleted or revoked user never knocks
//     again, so no per-user reconcile would ever remove them;
//   - the nftables guard after a group was added or deleted by the CLI.
//
// It also expires, hourly, the allowlist entry of every user who has not knocked
// for cfg.CleanupMaxAgeDays — on this host and, through the desired state, on
// every agent (a hub with firewall_backend: none included).
func (s *Server) Maintain() {
	s.fwMu.Lock()
	defer s.fwMu.Unlock()

	if err := s.fw.EnsureBase(); err != nil {
		log.Printf("maintain: firewall base: %v", err)
		return
	}
	if days := s.cfg.CleanupMaxAgeDays; days > 0 && time.Since(s.lastCleanup) >= cleanupEvery {
		s.lastCleanup = time.Now()
		if ugp, err := s.db.GetAllUserGroupPorts(); err != nil {
			log.Printf("maintain: cleanup: %v", err)
		} else if removed, err := s.fw.CleanupStale(days*86400, ugp); err != nil {
			log.Printf("maintain: cleanup: %v", err)
		} else if len(removed) > 0 {
			log.Printf("maintain: expired %d user(s) idle for over %d days: %v", len(removed), days, removed)
		}
	}
	desired, err := s.db.DesiredStateLocal()
	if err != nil {
		log.Printf("maintain: desired state: %v", err)
		return
	}
	rules := make([]firewall.Rule, 0, len(desired))
	for _, d := range desired {
		rules = append(rules, firewall.Rule{IP: d.IP, Port: d.Port, Proto: d.Proto, User: d.User, Group: d.Group})
	}
	added, removed, err := s.fw.ReconcileAll(rules)
	switch {
	case errors.Is(err, firewall.ErrInactive):
		// ufw is disabled: EnsureBase already warned; nothing changes until it is enabled.
	case err != nil:
		log.Printf("maintain: reconcile (partial, +%d/-%d): %v", added, removed, err)
	case added > 0 || removed > 0:
		log.Printf("maintain: repaired firewall drift (+%d/-%d rules)", added, removed)
	}
	if err := s.syncGuard(); err != nil {
		log.Printf("maintain: guard: %v", err)
	}
}

// syncGuardNow applies a group change to the guard immediately instead of at the
// next Maintain (same lock, so it never races Maintain's own guard rebuild).
func (s *Server) syncGuardNow() {
	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	if err := s.syncGuard(); err != nil {
		log.Printf("firewall guard: %v", err)
	}
}

// syncGuard closes every group's port to everyone its allow rules do not admit
// (nftables backend; a no-op for the others). With nft_guard: false it removes
// the guard, restoring the old accept-only behaviour.
func (s *Server) syncGuard() error {
	var ports []firewall.PortProto
	if s.cfg.NftGuard {
		groups, err := s.db.ListGroups()
		if err != nil {
			return err
		}
		for _, g := range groups {
			ports = append(ports, firewall.PortProto{Port: g.Port, Proto: g.Proto})
		}
	}
	return s.fw.SyncGuard(ports)
}
