package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"nft-okboy-fleet/internal/auth"
)

// clientIP extracts the real client IP, faithfully reproducing the Python
// _client_ip() H-9 model: proxy headers are trusted ONLY when the direct peer is
// in cfg.TrustedProxies, so a client reaching the server directly cannot spoof
// X-Real-IP / X-Forwarded-For to register an arbitrary IP in the allowlist.
//
//   - peer := host of r.RemoteAddr (port stripped).
//   - if peer is a trusted proxy: return X-Real-IP, else the RIGHTMOST entry of
//     X-Forwarded-For (the address the trusted proxy actually saw — nginx APPENDS
//     the real peer; the leftmost is client-supplied and spoofable), else peer.
//   - if peer is NOT trusted: the peer IS the real client.
func (s *Server) clientIP(r *http.Request) string {
	peer := hostOnly(r.RemoteAddr)

	if s.isTrustedProxy(peer) {
		if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
			return xri
		}
		if xff := r.Header.Get("X-Forwarded-For"); strings.TrimSpace(xff) != "" {
			parts := strings.Split(xff, ",")
			if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
				return last
			}
		}
		return peer
	}
	return peer
}

// isTrustedProxy reports whether peer is in cfg.TrustedProxies (default localhost
// is already baked into the config defaults, matching app.py's
// trusted_proxies=["127.0.0.1", "::1"] fallback).
func (s *Server) isTrustedProxy(peer string) bool {
	for _, t := range s.cfg.TrustedProxies {
		if t == peer {
			return true
		}
	}
	return false
}

// hostOnly returns the host portion of a "host:port" RemoteAddr, leaving a bare
// host (no port) untouched. r.RemoteAddr is normally "ip:port"; SplitHostPort
// fails on a bare value, in which case the original string is the host.
func hostOnly(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// throttleGate wraps the mux and rejects /api/ requests from an IP with too many
// recent auth failures (HTTP 429), the equivalent of Flask's @before_request
// _throttle_gate. It is centralized so the throttle covers knock, status, me/*,
// membership, and every admin endpoint uniformly (defense in depth with the
// nginx limit_req). Non-/api/ paths (/, /static/, /health) pass straight through.
func (s *Server) throttleGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		if err := auth.CheckIPThrottle(s.db, s.clientIP(r),
			s.cfg.ThrottleMaxFailures, s.cfg.ThrottleWindow); err != "" {
			// 429 with the same {"ok":false,"error":<msg>} envelope app.py returns.
			errJSON(w, http.StatusTooManyRequests, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// parseIntLenient parses a base-10 integer, used for the numeric-string JSON
// fields app.py coerces with int(...). A leading/trailing space is tolerated to
// match Python int(" 8080 ").
func parseIntLenient(s string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(s))
}

// pathInt reads a {name} path parameter as an int64. Go 1.22 ServeMux only routes
// a request to a {name} pattern when the segment is present, but it does not
// constrain the segment to digits the way Flask's <int:...> converter did, so we
// validate here and report a malformed id as 404 (the same status Flask's
// converter produced for a non-int path segment — a route miss).
func pathInt(r *http.Request, name string) (int64, bool) {
	raw := r.PathValue(name)
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}
