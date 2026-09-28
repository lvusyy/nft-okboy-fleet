package server

import (
	"net/http"
	"strings"
	"time"

	"nft-okboy-fleet/internal/auth"
	"nft-okboy-fleet/internal/db"
)

// issuer is the otpauth:// issuer label embedded in enrollment URIs (the app
// name shown in the authenticator). app.py used the default "ufw-okboy"; this Go
// port is branded "nft-okboy" consistently (matching /health service + rule prefix).
const issuer = "nft-okboy"

// totpFailReason tags every failed TOTP check in failed_attempts — step-up,
// re-enroll, disable and activate alike — so totpLocked counts them together.
const totpFailReason = "Invalid TOTP code"

// totpAttempt runs one TOTP check for user under the per-account cap. Checking
// the cap, verifying the code and recording a failure happen under one lock, so
// concurrent guesses cannot all pass the check before any failure is counted.
// An empty code is not a guess — clients send the request once without a code
// to learn that one is required — so it is neither verified nor counted.
//
// verify performs the endpoint's own check (with or without consuming the code
// for replay protection). ok reports a valid code; answered reports that a
// response was already written (429 over the cap, 500 on a DB error). With
// ok == false and answered == false the caller writes its usual rejection.
func (s *Server) totpAttempt(w http.ResponseWriter, r *http.Request, user *db.User, code, action string,
	verify func() (ok, replayed bool, err error)) (ok, answered bool) {
	if strings.TrimSpace(code) == "" {
		return false, false
	}
	s.totpMu.Lock()
	defer s.totpMu.Unlock()
	if s.totpLocked(w, user) {
		return false, true
	}
	ok, replayed, err := verify()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "Internal error")
		return false, true
	}
	if !ok {
		s.totpFailed(r, user, action, replayed)
	}
	return ok, false
}

// totpLocked answers 429 and returns true when user has failed too many TOTP
// checks within the throttle window. The count is per ACCOUNT, from any IP and
// across every TOTP endpoint: with the per-IP throttle alone, someone holding an
// admin's HMAC secret could spread 6-digit guesses over many addresses (or over
// the endpoints that did not count failures) until one hit.
func (s *Server) totpLocked(w http.ResponseWriter, user *db.User) bool {
	if s.cfg.ThrottleMaxFailures <= 0 {
		return false
	}
	n, err := s.db.CountRecentUserFailures(user.Username, totpFailReason, s.cfg.ThrottleWindow)
	if err != nil || n < s.cfg.ThrottleMaxFailures {
		return false // a counting error does not deny, matching CheckIPThrottle
	}
	errJSON(w, http.StatusTooManyRequests, "Too many failed TOTP codes; try again later")
	return true
}

// totpFailed records a failed TOTP check: an audit row (action, with "replay"
// as detail when the code was valid but already used) plus a failed attempt that
// counts toward the caller IP's throttle and the account's totpLocked cap.
func (s *Server) totpFailed(r *http.Request, user *db.User, action string, replayed bool) {
	var detail *string
	if replayed {
		detail = strPtr("replay")
	}
	_ = s.db.LogAudit(user.Username, action, strPtr(user.Username), detail)
	ip := s.requestIP(r)
	_ = s.db.RecordFailedAttempt(strPtr(user.Username), &ip, totpFailReason)
}

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
//     comes from the X-TOTP-Code header or the totp_code body field. A missing
//     code, or a wrong/replayed one, returns
//     403 {"ok":false,"error":"Valid TOTP code required","totp_required":true};
//     a wrong/replayed one also logs stepup_failed and records a failed attempt
//     toward the IP throttle and the account's TOTP cap (so an already-admin-
//     authenticated caller cannot brute-force the 6-digit code — the HMAC
//     throttle never sees these). Past the cap every TOTP check answers 429.
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
		valid, answered := s.totpAttempt(w, r, user, code, "stepup_failed",
			func() (bool, bool, error) { return s.consumeTOTP(user, code) })
		if answered {
			return true
		}
		if !valid {
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
// ok only for a fresh, valid code (atomically advancing totp_last_counter when
// replay protection is on: a single UPDATE advances it only if the code has not
// been used, so two concurrent requests with one code cannot both win), replayed
// for a valid but already-used code, and a non-nil error only on a DB failure.
// Step-up, re-enroll and disable all use it, so a captured code is never good
// for its whole ±window.
func (s *Server) consumeTOTP(user *db.User, code string) (ok, replayed bool, err error) {
	secret := ""
	if user.TOTPSecret != nil {
		secret = *user.TOTPSecret
	}
	matched := auth.VerifyTOTPCounter(secret, code, time.Now().Unix())
	if matched == nil {
		return false, false, nil
	}
	if !s.cfg.TOTPReplayProtection {
		return true, false, nil
	}
	consumed, err := s.db.ConsumeTOTPCounter(user.ID, *matched)
	if err != nil {
		return false, false, err
	}
	return consumed, !consumed, nil
}

// totpEnroll begins TOTP enrollment (admin only): generate a secret + otpauth URI.
// The secret is stored but NOT active until /activate confirms a code. Mirrors
// app.py admin_totp_enroll, including the re-enrollment guard: when TOTP is
// already enabled, the admin must prove current possession (a valid current code)
// before the secret is overwritten — otherwise a stolen admin session with no
// code could replace/disable an enabled admin's 2FA. A first-time enroll is always
// allowed so require_admin_totp cannot deadlock the very enrollment it demands.
func (s *Server) totpEnroll(w http.ResponseWriter, r *http.Request) {
	user, err := auth.RequireAdmin(s.db, r.Header.Get("Authorization"), s.cfg.SignatureTTL, s.requestIP(r))
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
		ok, answered := s.totpAttempt(w, r, user, recode, "totp_reenroll_failed",
			func() (bool, bool, error) { return s.consumeTOTP(user, recode) })
		if answered {
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
	user, err := auth.RequireAdmin(s.db, r.Header.Get("Authorization"), s.cfg.SignatureTTL, s.requestIP(r))
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
	ok, answered := s.totpAttempt(w, r, user, code, "totp_activate_failed",
		func() (bool, bool, error) {
			return auth.VerifyTOTP(*user.TOTPSecret, code, time.Now().Unix()), false, nil
		})
	if answered {
		return
	}
	if !ok {
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
	user, err := auth.RequireAdmin(s.db, r.Header.Get("Authorization"), s.cfg.SignatureTTL, s.requestIP(r))
	if err != "" {
		s.adminError(w, err)
		return
	}
	if user.TOTPEnabled {
		body := readJSON(r)
		code := jsonString(body, "totp_code")
		// Replay-protected consume (RFC 6238 §5.2): disabling 2FA is security-
		// critical, so a captured/replayed code must not authorize it.
		ok, answered := s.totpAttempt(w, r, user, code, "totp_disable_failed",
			func() (bool, bool, error) { return s.consumeTOTP(user, code) })
		if answered {
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
