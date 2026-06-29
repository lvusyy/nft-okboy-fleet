package server

import (
	"net/http"
	"strings"

	"nft-okboy-fleet/internal/db"
	"nft-okboy-fleet/internal/firewall"
)

// authNode authenticates an agent by its bearer enrollment token. Header form is
// "Authorization: Bearer <token>"; the hub stores only sha256(token), so it
// hashes the presented token and looks the node up by hash. Returns the node, or
// writes 401/500 and returns nil. last_seen is bumped on every authenticated call
// so the fleet view shows agent liveness.
func (s *Server) authNode(w http.ResponseWriter, r *http.Request) *db.Node {
	const pfx = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, pfx) {
		errJSON(w, http.StatusUnauthorized, "Missing or invalid node token")
		return nil
	}
	token := strings.TrimSpace(h[len(pfx):])
	if token == "" {
		errJSON(w, http.StatusUnauthorized, "Missing or invalid node token")
		return nil
	}
	node, err := s.db.GetNodeByTokenHash(db.HashToken(token))
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return nil
	}
	if node == nil {
		errJSON(w, http.StatusUnauthorized, "Invalid node token")
		return nil
	}
	_ = s.db.TouchNode(node.ID)
	return node
}

// nodeDesiredState returns the allow rules the calling node's agent must enforce.
// Auth: node bearer token (a node may read ONLY its own desired state — the token
// scopes it to one node, so a compromised agent learns nothing about the fleet).
// Each rule carries the same "<prefix>:<user>:<group>" comment the firewall
// backends key on, so the agent reconciles its local firewall to exactly this set.
func (s *Server) nodeDesiredState(w http.ResponseWriter, r *http.Request) {
	node := s.authNode(w, r)
	if node == nil {
		return
	}
	desired, err := s.db.DesiredStateForNode(node.ID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return
	}
	rules := make([]map[string]any, 0, len(desired))
	for _, d := range desired {
		rules = append(rules, map[string]any{
			"ip":      d.IP,
			"port":    d.Port,
			"proto":   d.Proto,
			"user":    d.User,
			"group":   d.Group,
			"comment": firewall.Comment(s.cfg.RulePrefix, d.User, d.Group),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"node":   node.Name,
		"prefix": s.cfg.RulePrefix,
		"rules":  rules,
	})
}
