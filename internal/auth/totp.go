package auth

// TOTP (RFC 6238) — step-up verification for admin-sensitive operations.
//
// Stdlib-only HOTP/TOTP (no third-party dependency). HMAC-SHA1 is the RFC
// default and what authenticator apps (Google Authenticator, Authy, ...) expect
// — the SHA-1 collision weakness does NOT affect HMAC-SHA1's use here.
// Correctness is pinned to the RFC 6238 Appendix B test vectors in totp_test.go.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
)

const (
	totpStep   = 30 // time step in seconds
	totpDigits = 6  // number of code digits
	totpWindow = 1  // ± steps tolerated for clock skew
)

// GenerateTOTPSecret returns a fresh base32 TOTP secret (160-bit, unpadded and
// uppercase — authenticator-app friendly).
func GenerateTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read never returns a short read without an error; a failure
		// here means the OS CSPRNG is unavailable, which is unrecoverable.
		panic("auth: crypto/rand failed: " + err.Error())
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
}

// b32decode decodes an unpadded or padded base32 secret to raw key bytes,
// re-padding to a multiple of 8 with '=' and upper-casing first. Invalid input
// yields nil (callers treat a nil/empty key as a non-matching code).
func b32decode(secret string) []byte {
	s := strings.ToUpper(secret)
	if pad := (8 - len(s)%8) % 8; pad != 0 {
		s += strings.Repeat("=", pad)
	}
	key, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return key
}

// hotp implements RFC 4226 HOTP: dynamic-truncated HMAC-SHA1, zero-padded to
// totpDigits decimal digits.
func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0F
	truncated := (uint32(sum[offset]&0x7F) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, truncated%mod)
}

// TOTPNow returns the current TOTP code for secret at unix time t (RFC 6238).
func TOTPNow(secret string, t int64) string {
	return hotp(b32decode(secret), uint64(t/totpStep))
}

// VerifyTOTPCounter constant-time verifies code and returns the MATCHED absolute
// counter (t/step + w), or nil if no match within ±totpWindow steps.
//
// The window absorbs clock skew between server and authenticator (±1 step =
// ±30s). The caller can persist the returned counter to reject replay of an
// already-consumed code (RFC 6238 §5.2). Returns nil for an empty secret/code.
func VerifyTOTPCounter(secret, code string, t int64) *int64 {
	if secret == "" || code == "" {
		return nil
	}
	code = strings.TrimSpace(code)
	key := b32decode(secret)
	counter := t / totpStep
	for w := int64(-totpWindow); w <= totpWindow; w++ {
		candidate := counter + w
		if hmac.Equal([]byte(hotp(key, uint64(candidate))), []byte(code)) {
			matched := candidate
			return &matched
		}
	}
	return nil
}

// VerifyTOTP constant-time verifies code against secret, tolerating ±totpWindow
// steps. Thin bool wrapper over VerifyTOTPCounter. Returns false for an empty
// secret/code.
func VerifyTOTP(secret, code string, t int64) bool {
	return VerifyTOTPCounter(secret, code, t) != nil
}

// TOTPURI builds an otpauth:// URI for QR/manual enrollment in an authenticator
// app.
func TOTPURI(secret, username, issuer string) string {
	label := url.QueryEscape(issuer + ":" + username)
	return fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&digits=6&period=30",
		label, secret, url.QueryEscape(issuer))
}
