package auth

import "testing"

// rfcSecret is the RFC 6238 Appendix B seed, the ASCII string
// "12345678901234567890" (20 bytes) expressed in base32 for our API.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// TestTOTPNowRFC6238Vectors pins HOTP/TOTP correctness to the RFC 6238
// Appendix B SHA-1 test vectors (6-digit truncation). If any of these drift the
// wire format has diverged from the standard and every authenticator app breaks.
func TestTOTPNowRFC6238Vectors(t *testing.T) {
	cases := []struct {
		time int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		if got := TOTPNow(rfcSecret, c.time); got != c.code {
			t.Errorf("TOTPNow(t=%d) = %q, want %q", c.time, got, c.code)
		}
	}
}

// TestVerifyTOTPCounterMatch verifies that the current code matches and returns
// the expected absolute counter (t/step), while a wrong code returns nil.
func TestVerifyTOTPCounterMatch(t *testing.T) {
	const now int64 = 1111111109
	code := TOTPNow(rfcSecret, now)

	got := VerifyTOTPCounter(rfcSecret, code, now)
	if got == nil {
		t.Fatalf("VerifyTOTPCounter(current code) = nil, want non-nil")
	}
	if want := now / totpStep; *got != want {
		t.Errorf("matched counter = %d, want %d", *got, want)
	}

	if VerifyTOTPCounter(rfcSecret, "000000", now) != nil {
		// "000000" is not the code at this timestamp (it is "081804").
		t.Errorf("VerifyTOTPCounter(wrong code) = non-nil, want nil")
	}
}

// TestVerifyTOTPCounterIncrementsWithTime verifies the returned counter advances
// as time crosses step boundaries (one full step apart => +1 counter).
func TestVerifyTOTPCounterIncrementsWithTime(t *testing.T) {
	const t1 int64 = 1111111111
	t2 := t1 + totpStep // one full 30s step later

	c1 := VerifyTOTPCounter(rfcSecret, TOTPNow(rfcSecret, t1), t1)
	c2 := VerifyTOTPCounter(rfcSecret, TOTPNow(rfcSecret, t2), t2)
	if c1 == nil || c2 == nil {
		t.Fatalf("expected non-nil counters, got c1=%v c2=%v", c1, c2)
	}
	if *c2 != *c1+1 {
		t.Errorf("counter did not increment by one step: c1=%d c2=%d", *c1, *c2)
	}
}

// TestVerifyTOTPBool exercises the bool wrapper and the empty-input guards.
func TestVerifyTOTPBool(t *testing.T) {
	const now int64 = 59
	if !VerifyTOTP(rfcSecret, "287082", now) {
		t.Errorf("VerifyTOTP(valid RFC code) = false, want true")
	}
	if VerifyTOTP(rfcSecret, "000000", now) {
		t.Errorf("VerifyTOTP(wrong code) = true, want false")
	}
	if VerifyTOTP("", "287082", now) {
		t.Errorf("VerifyTOTP(empty secret) = true, want false")
	}
	if VerifyTOTP(rfcSecret, "", now) {
		t.Errorf("VerifyTOTP(empty code) = true, want false")
	}
}

// TestVerifyTOTPWindow confirms the ±1 step skew tolerance: a code from the
// previous and next step still verifies against the current time.
func TestVerifyTOTPWindow(t *testing.T) {
	const now int64 = 1234567890
	prev := TOTPNow(rfcSecret, now-totpStep)
	next := TOTPNow(rfcSecret, now+totpStep)
	if !VerifyTOTP(rfcSecret, prev, now) {
		t.Errorf("previous-step code did not verify within window")
	}
	if !VerifyTOTP(rfcSecret, next, now) {
		t.Errorf("next-step code did not verify within window")
	}
}

// TestGenerateTOTPSecret sanity-checks the generated secret: unpadded, uppercase
// base32, and usable as a round-trip TOTP key.
func TestGenerateTOTPSecret(t *testing.T) {
	s := GenerateTOTPSecret()
	if s == "" {
		t.Fatal("GenerateTOTPSecret returned empty string")
	}
	for _, r := range s {
		if r == '=' {
			t.Errorf("secret should be unpadded, got %q", s)
			break
		}
		if !(r >= 'A' && r <= 'Z') && !(r >= '2' && r <= '7') {
			t.Errorf("secret has non-base32 rune %q in %q", r, s)
			break
		}
	}
	// A freshly generated secret must verify its own current code.
	const now int64 = 1700000000
	if !VerifyTOTP(s, TOTPNow(s, now), now) {
		t.Errorf("generated secret failed self round-trip")
	}
}

// TestTOTPURI checks the otpauth URI shape and URL-escaping of the label/issuer.
func TestTOTPURI(t *testing.T) {
	got := TOTPURI("ABC234", "alice", "NFT-OkBoy")
	want := "otpauth://totp/NFT-OkBoy%3Aalice?secret=ABC234&issuer=NFT-OkBoy&digits=6&period=30"
	if got != want {
		t.Errorf("TOTPURI() = %q, want %q", got, want)
	}
}
