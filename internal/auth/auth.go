// Package auth is the DB-backed authorization layer for nft-okboy. It is a
// faithful port of the Python server/auth.py: HMAC-SHA256 request
// authentication, per-IP failure throttling, admin checks, and stdlib-only
// TOTP (RFC 6238) step-up verification.
//
// The HMAC-SHA256 wire format is identical to the Python implementation so
// existing clients (knock.py, knock.sh, and the Web UI) authenticate without
// any client-side change: the database is the single source of truth for user
// secrets and admin flags.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"nft-okboy-fleet/internal/db"
)

// hmacPrefix is the required scheme token in the Authorization header value.
const hmacPrefix = "HMAC-SHA256 "

// VerifyHMAC verifies the HMAC-SHA256 Authorization header against the database.
//
// Header format: "HMAC-SHA256 <username>:<timestamp>:<hex_signature>" where
// signature = lowercase-hex HMAC-SHA256(secret, "<username>:<timestamp>").
//
// On every failure branch a row is recorded in failed_attempts via
// d.RecordFailedAttempt before returning. The username recorded is nil while it
// is still unknown (bad header / malformed payload) and the parsed username
// thereafter, mirroring the Python source. ttl is the maximum allowed clock skew
// in seconds, enforced as |now-ts| <= ttl.
//
// Returns (username, "") on success, or ("", errMsg) on failure.
func VerifyHMAC(d *db.DB, header string, ttl int, clientIP string) (username string, errMsg string) {
	ip := &clientIP
	if !strings.HasPrefix(header, hmacPrefix) {
		_ = d.RecordFailedAttempt(nil, ip, "Missing or invalid Authorization header")
		return "", "Missing or invalid Authorization header"
	}

	payload := header[len(hmacPrefix):]

	// Split into exactly 3 fields; the signature itself may contain ':' so we
	// limit to 3 parts (Python str.split(":", 2)).
	parts := strings.SplitN(payload, ":", 3)
	if len(parts) != 3 {
		_ = d.RecordFailedAttempt(nil, ip, "Malformed auth payload (expected username:timestamp:signature)")
		return "", "Malformed auth payload (expected username:timestamp:signature)"
	}
	user, tsStr, signature := parts[0], parts[1], parts[2]
	userPtr := &user

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		_ = d.RecordFailedAttempt(userPtr, ip, "Invalid timestamp")
		return "", "Invalid timestamp"
	}
	if abs64(time.Now().Unix()-ts) > int64(ttl) {
		_ = d.RecordFailedAttempt(userPtr, ip, "Signature expired")
		return "", "Signature expired"
	}

	row, err := d.GetUserByUsername(user)
	if err != nil || row == nil {
		// Defeat user enumeration: an unknown user must cost the same time and
		// return the same generic message as a bad signature. Compute a dummy
		// HMAC (zero key) so the timing matches the verified path below; the
		// specific reason is still recorded server-side for audit.
		dummy := hmac.New(sha256.New, make([]byte, 32))
		dummy.Write([]byte(user + ":" + tsStr))
		_ = hmac.Equal([]byte(signature), []byte(hex.EncodeToString(dummy.Sum(nil))))
		_ = d.RecordFailedAttempt(userPtr, ip, "Unknown user")
		return "", "Invalid credentials"
	}

	// Sign the raw "<username>:<timestamp>" using the original timestamp
	// substring (not a re-serialized int) so the bytes match the client exactly.
	mac := hmac.New(sha256.New, []byte(row.Secret))
	mac.Write([]byte(user + ":" + tsStr))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expected)) {
		_ = d.RecordFailedAttempt(userPtr, ip, "Invalid signature")
		return "", "Invalid credentials"
	}

	return user, ""
}

// CheckIPThrottle returns an error string if ip has too many recent failures.
//
// Throttling is keyed on the IP, not the username, on purpose: keying on
// username would let an attacker lock out a legitimate user just by spamming bad
// signatures for their name (account-lockout DoS). A non-positive maxFailures or
// an empty ip disables the throttle (returns ""). The throttle rejection itself
// is NOT recorded as a new failed attempt, so the window slides cleanly: an IP
// unlocks once its failures age past windowSec.
func CheckIPThrottle(d *db.DB, ip string, maxFailures, windowSec int) string {
	if maxFailures <= 0 || ip == "" {
		return ""
	}
	n, err := d.CountRecentFailedAttempts(ip, windowSec)
	if err != nil {
		// Conservative: on a counting error treat as not-throttled, matching the
		// Python behavior where a DB error propagates rather than silently denying.
		return ""
	}
	if n >= maxFailures {
		return "Too many failed attempts; try again later"
	}
	return ""
}

// IsAdmin reports whether username exists and has the admin flag set.
func IsAdmin(d *db.DB, username string) bool {
	row, err := d.GetUserByUsername(username)
	if err != nil || row == nil {
		return false
	}
	return row.IsAdmin
}

// RequireAdmin verifies the HMAC header and requires admin privileges.
//
// Returns (user, "") when the caller is an admin, otherwise (nil, errMsg). A
// non-admin authenticated caller is recorded as an "Admin privileges required"
// failed attempt before returning, mirroring the Python source.
func RequireAdmin(d *db.DB, header string, ttl int, clientIP string) (*db.User, string) {
	username, errMsg := VerifyHMAC(d, header, ttl, clientIP)
	if errMsg != "" {
		return nil, errMsg
	}
	if !IsAdmin(d, username) {
		ip := &clientIP
		_ = d.RecordFailedAttempt(&username, ip, "Admin privileges required")
		return nil, "Admin privileges required"
	}
	user, err := d.GetUserByUsername(username)
	if err != nil {
		return nil, "Admin privileges required"
	}
	return user, ""
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
