package server

import (
	"testing"

	"nft-okboy-fleet/internal/config"
)

// TestRoutesRegister guards against a ServeMux pattern-conflict panic at route
// registration. Go 1.22's mux panics when two patterns overlap with neither being
// more specific — e.g. a "/api/" subtree catch-all conflicts with "GET /". Neither
// `go build` nor `go vet` calls Routes(), so a registration panic ships silently
// and only surfaces when `okboy serve` crash-loops on startup. This test invokes
// the real registration path so `go test` catches the whole class of bug.
func TestRoutesRegister(t *testing.T) {
	// Route registration builds the mux and wraps it in the throttle gate; it does
	// not dereference db/fw, so nil deps are fine here (a non-nil cfg is passed for
	// safety since the gate closure captures it).
	s := NewServer(nil, nil, &config.Config{})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Routes() panicked while registering patterns: %v", r)
		}
	}()
	if s.Routes() == nil {
		t.Fatal("Routes() returned a nil handler")
	}
}
