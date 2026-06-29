package server

import (
	"net/http"
	"time"

	"nft-okboy-fleet/internal/auth"
	"nft-okboy-fleet/internal/db"
)

// issuer is the otpauth:// issuer label embedded in enrollment URIs (the app
// name shown in the authenticator). app.py used the default "ufw-okboy"; this Go
// port is branded "okboy" consistently (matching /health service + rule prefix).
const issuer = "okboy"

// stepUp is the TOTP step-up gate for sensitive admin ops, a faithful port of
// app.py's _step_up_error(user). It returns true when it has short-circuited the
// request (a response was already written) and false when the caller may proceed.
//
// body MUST be the already-parsed request body (the caller parses it once and
// reuses it for its own fields), because the step-up code may live in the
// "totp_code" body field and the HTTP body is a one-shot reader.
//
// Logic, 1:1 with the Python source:
//   - user has TOTP enabled → a valid, non-replayed code is mandatory. The code
//     comes from the X-TOTP-Code header or the totp_code body field. A missing/
//     wrong/replayed code logs stepup_failed, records a failed attempt toward the
//     IP throttle (so an already-admin-authenticated caller cannot brute-force the
//     6-digit code unbounded — the HMAC throttle never sees these), and returns
//     403 {"ok":false,"error":"Valid TOTP code required","totp_required":true}.
//     On success, when replay protection is on, the matched counter is persisted.
//   - user without TOTP + require_admin_totp config → blocked until enrolled:
//     403 {"ok":false,"error":"Admin TOTP enrollment required before this action",
//     "totp_enroll_required":true}.
//   - otherwise → proceed (false).
func (s *Server) stepUp(w http.ResponseWriter, r *http.Request, user *db.User, body map[string]any) bool {
	if user.TOTPEnabled {
		code := r.Header.Get("X-TOTP-Code")
		if code == "" {
			code = jsonString(body, "totp_code")
		}
		secret := ""
		if user.TOTPSecret != nil {
			secret = *user.TOTPSecret
		}
		matched := auth.VerifyTOTPCounter(secret, code, time.Now().Unix())
		valid := matched != nil
		replayed := false
		if valid && s.cfg.TOTPReplayProtection {
			// Atomically consume the counter: a single UPDATE advances it only if
			// the code hasn't been used, closing the check-then-set replay race
			// two concurrent step-ups with the same code could otherwise win.
			consumed, cerr := s.db.ConsumeTOTPCounter(user.ID, *matched)
			if cerr != nil {
				errJSON(w, http.StatusInternalServerError, "Internal error")
				return true
			}
			if !consumed {
				valid, replayed = false, true
			}
		}
		if !valid {
			detail := (*string)(nil)
			if replayed {
				detail = strPtr("replay")
			}
			_ = s.db.LogAudit(user.Username, "stepup_failed", strPtr(user.Username), detail)
			// Count a bad/replayed step-up toward the per-IP throttle.
			ip := s.clientIP(r)
			_ = s.db.RecordFailedAttempt(strPtr(user.Username), &ip, "Invalid TOTP step-up")
			writeJSON(w, http.StatusForbidden, map[string]any{
				"ok":            false,
				"error":         "Valid TOTP code required",
				"totp_required": true,
			})
			return true
		}
		return false
	}
	if s.cfg.RequireAdminTOTP {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":                   false,
			"error":                "Admin TOTP enrollment required before this action",
			"totp_enroll_required": true,
		})
		return true
	}
	return false
}

// consumeTOTP verifies a counter-based TOTP code with replay protection,
// consuming it on success — the Go analogue of app.py's _consume_totp. It returns
// (true, nil) only for a fresh, valid code (atomically advancing totp_last_counter
// when replay protection is on), (false, nil) for an invalid OR replayed code, and
// a non-nil error only on a DB failure. The TOTP disable / re-enroll paths use
// this so the most security-critical 2FA operations honor the same replay
// protection as the step-up gate — a bare VerifyTOTP would let one captured code
// stay valid for its whole ±window.
func (s *Server) consumeTOTP(user *db.User, code string) (bool, error) {
	secret := ""
	if user.TOTPSecret != nil {
		secret = *user.TOTPSecret
	}
	matched := auth.VerifyTOTPCounter(secret, code, time.Now().Unix())
	if matched == nil {
		return false, nil
	}
	if !s.cfg.TOTPReplayProtection {
		return true, nil
	}
	return s.db.ConsumeTOTPCounter(user.ID, *matched)
}

// totpEnroll begins TOTP enrollment (admin only): generate a secret + otpauth URI.
// The secret is stored but NOT active until /activate confirms a code. Mirrors
// app.py admin_totp_enroll, including the re-enrollment guard: when TOTP is
// already enabled, the admin must prove current possession (a valid current code)
// before the secret is overwritten — otherwise a stolen admin session with no
// code could replace/disable an enabled admin's 2FA. A first-time enroll is always
// allowed so require_admin_totp cannot deadlock the very enrollment it demands.
func (s *Server) totpEnroll(w http.ResponseWriter, r *http.Request) {
	user, err := auth.RequireAdmin(s.db, r.Header.Get("Authorization"), s.cfg.SignatureTTL, s.clientIP(r))
	if err != "" {
		s.adminError(w, err)
		return
	}
	body := readJSON(r)
	if user.TOTPEnabled {
		recode := r.Header.Get("X-TOTP-Code")
		if recode == "" {
			recode = jsonString(body, "totp_code")
		}
		// Replay-protected consume (RFC 6238 §5.2): re-enrollment replaces the
		// 2FA secret, so a captured/replayed code must not authorize it.
		ok, cerr := s.consumeTOTP(user, recode)
		if cerr != nil {
			errJSON(w, http.StatusInternalServerError, "Internal error")
			return
		}
		if !ok {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"ok":            false,
				"error":         "Valid TOTP code required to re-enroll",
				"totp_required": true,
			})
			return
		}
	}
	secret := auth.GenerateTOTPSecret()
	if e := s.db.SetTOTPSecret(user.ID, secret); e != nil {
		errJSON(w, http.StatusInternalServerError, "Failed to store TOTP secret")
		return
	}
	_ = s.db.LogAudit(user.Username, "totp_enroll_start", strPtr(user.Username), nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"secret":      secret,
		"otpauth_uri": auth.TOTPURI(secret, user.Username, issuer),
	})
}

// totpActivate activates a pending enrollment by confirming a code (admin only).
// Mirrors app.py admin_totp_activate: 400 if there is no pending secret, 400 on an
// invalid code, else enable TOTP.
func (s *Server) totpActivate(w http.ResponseWriter, r *http.Request) {
	user, err := auth.RequireAdmin(s.db, r.Header.Get("Authorization"), s.cfg.SignatureTTL, s.clientIP(r))
	if err != "" {
		s.adminError(w, err)
		return
	}
	if user.TOTPSecret == nil || *user.TOTPSecret == "" {
		errJSON(w, http.StatusBadRequest, "No pending enrollment; call enroll first")
		return
	}
	body := readJSON(r)
	code := jsonString(body, "totp_code")
	if !auth.VerifyTOTP(*user.TOTPSecret, code, time.Now().Unix()) {
		errJSON(w, http.StatusBadRequest, "Invalid code")
		return
	}
	if e := s.db.EnableTOTP(user.ID); e != nil {
		errJSON(w, http.StatusInternalServerError, "Failed to enable TOTP")
		return
	}
	_ = s.db.LogAudit(user.Username, "totp_activate", strPtr(user.Username), nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "totp_enabled": true})
}

// totpDisable disables TOTP for the calling admin. Mirrors app.py
// admin_totp_disable: when TOTP is enabled a current code is required (403 on a
// wrong code), then the secret is cleared and the flag reset.
func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	user, err := auth.RequireAdmin(s.db, r.Header.Get("Authorization"), s.cfg.SignatureTTL, s.clientIP(r))
	if err != "" {
		s.adminError(w, err)
		return
	}
	if user.TOTPEnabled {
		body := readJSON(r)
		code := jsonString(body, "totp_code")
		// Replay-protected consume (RFC 6238 §5.2): disabling 2FA is security-
		// critical, so a captured/replayed code must not authorize it.
		ok, cerr := s.consumeTOTP(user, code)
		if cerr != nil {
			errJSON(w, http.StatusInternalServerError, "Internal error")
			return
		}
		if !ok {
			errJSON(w, http.StatusForbidden, "Valid TOTP code required to disable")
			return
		}
	}
	if e := s.db.DisableTOTP(user.ID); e != nil {
		errJSON(w, http.StatusInternalServerError, "Failed to disable TOTP")
		return
	}
	_ = s.db.LogAudit(user.Username, "totp_disable", strPtr(user.Username), nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "totp_enabled": false})
}
