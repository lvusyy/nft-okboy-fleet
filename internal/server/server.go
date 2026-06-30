// Package server is the HTTP layer: a faithful port of the Flask routes in the
// Python server/app.py. It wires stdlib net/http (Go 1.22 method+path ServeMux
// patterns) to the db, firewall, auth, and config packages, mirroring every
// route and response shape so the UNCHANGED single-file web client (internal/
// static/index.html) works against it without modification.
//
// Endpoint behavior (auth order, status codes, error strings, the knock
// reconcile-then-record flow, the TOTP step-up gate, the H-9 client-IP model) is
// kept 1:1 with app.py; see the per-handler comments in knock.go / admin.go /
// totp.go.
package server

import (
	"net/http"

	"nft-okboy-fleet/internal/config"
	"nft-okboy-fleet/internal/db"
	"nft-okboy-fleet/internal/firewall"
)

// Server holds the shared dependencies every handler needs. It is the Go
// analogue of the closure state Flask's create_app() captured (db, ufw, cfg,
// ttl, throttle/anomaly thresholds — all derived from cfg here).
type Server struct {
	db      *db.DB
	fw      *firewall.Manager
	cfg     *config.Config
	version string
}

// NewServer constructs a Server from its dependencies. Version defaults to "dev"
// until SetVersion is called by main (which reads the VERSION file / build flag),
// mirroring how app.py reads VERSION as the single source of truth.
func NewServer(d *db.DB, fw *firewall.Manager, cfg *config.Config) *Server {
	return &Server{db: d, fw: fw, cfg: cfg, version: "dev"}
}

// SetVersion sets the version string reported by /health (and the X-... surfaces
// that might use it). main injects the VERSION-file value here.
func (s *Server) SetVersion(v string) {
	if v != "" {
		s.version = v
	}
}

// Routes builds the full route table and wraps it in the per-IP throttle gate
// (the equivalent of Flask's @before_request _throttle_gate). Go 1.22 method+path
// patterns give us the same routing app.py expressed with @app.route(methods=...);
// path params are read in-handler via r.PathValue(...).
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// ---- Client API ---- //
	mux.HandleFunc("POST /api/knock", s.knock)
	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("GET /api/me/groups", s.myGroups)
	mux.HandleFunc("PATCH /api/me/membership/{group_id}", s.selfToggleMembership)
	mux.HandleFunc("PATCH /api/membership/{user_id}/{group_id}", s.toggleMembership)

	// ---- Node API (agent pull; bearer node-token) ---- //
	mux.HandleFunc("GET /api/v1/node/desired-state", s.nodeDesiredState)

	// ---- Admin: users ---- //
	mux.HandleFunc("GET /api/admin/users", s.adminListUsers)
	mux.HandleFunc("POST /api/admin/users", s.adminCreateUser)
	mux.HandleFunc("DELETE /api/admin/users/{user_id}", s.adminDeleteUser)
	mux.HandleFunc("POST /api/admin/users/{user_id}/admin", s.adminSetAdmin)
	mux.HandleFunc("GET /api/admin/users/{user_id}/groups", s.adminUserGroups)
	mux.HandleFunc("POST /api/admin/users/{user_id}/groups", s.adminAddMembership)
	mux.HandleFunc("POST /api/admin/users/{user_id}/revoke", s.adminRevokeUser)

	// ---- Admin: memberships ---- //
	mux.HandleFunc("POST /api/admin/memberships/remove", s.adminRemoveMembership)

	// ---- Admin: groups ---- //
	mux.HandleFunc("GET /api/admin/groups", s.adminListGroups)
	mux.HandleFunc("POST /api/admin/groups", s.adminCreateGroup)
	mux.HandleFunc("DELETE /api/admin/groups/{group_id}", s.adminDeleteGroup)

	// ---- Admin: audit ---- //
	mux.HandleFunc("GET /api/admin/audit", s.adminListAudit)

	// ---- Admin: fleet ---- //
	mux.HandleFunc("GET /api/admin/nodes", s.adminListNodes)

	// ---- Admin: TOTP ---- //
	mux.HandleFunc("POST /api/admin/totp/enroll", s.totpEnroll)
	mux.HandleFunc("POST /api/admin/totp/activate", s.totpActivate)
	mux.HandleFunc("DELETE /api/admin/totp", s.totpDisable)

	// ---- Health (no auth) ---- //
	mux.HandleFunc("GET /health", s.health)

	// ---- Web client (embedded SPA) ---- //
	// "/" serves index.html; "/static/..." also serves the same single-file SPA
	// so the app keeps working if the client requests its old static path. The
	// throttle gate only guards "/api/", so these pass through untouched.
	mux.HandleFunc("GET /", s.serveIndex)
	mux.HandleFunc("GET /static/", s.serveIndex)

	return s.throttleGate(mux)
}

// health is the no-auth liveness probe. Shape mirrors app.py's /health plus the
// version field the Go build surfaces: {"ok":true,"service":"nft-okboy","version":...}.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "nft-okboy",
		"version": s.version,
	})
}
