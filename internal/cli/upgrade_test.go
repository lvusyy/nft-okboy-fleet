package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestTrustedDigestFromAPI: the digest GitHub reports for the asset is used, and
// only for the asset asked for (never a neighbour's, never a malformed value).
func TestTrustedDigestFromAPI(t *testing.T) {
	good := sha("binary")
	rel := &release{TagName: "v1.0.0", Assets: []releaseAsset{
		{Name: "nft-okboy-linux-arm64", Digest: "sha256:" + sha("other")},
		{Name: "nft-okboy-linux-386", Digest: "sha256:not-hex"},
		{Name: "nft-okboy-linux-amd64", Digest: "sha256:" + strings.ToUpper(good)},
	}}
	got, err := trustedDigest(rel, "x/y", "v1.0.0", "nft-okboy-linux-amd64")
	if err != nil || got != good {
		t.Fatalf("want %s, got %q (err %v)", good, got, err)
	}
}

// TestDigestFromSums parses sha256sum output (text and binary mode) and rejects
// manifests without a well-formed entry for the asset.
func TestDigestFromSums(t *testing.T) {
	a, b := sha("a"), sha("b")
	sums := []byte(a + "  nft-okboy-linux-arm64\n" + b + " *nft-okboy-linux-amd64\n")
	if got, err := digestFromSums(sums, "nft-okboy-linux-amd64"); err != nil || got != b {
		t.Fatalf("want %s, got %q (err %v)", b, got, err)
	}
	if _, err := digestFromSums(sums, "nft-okboy-linux-386"); err == nil {
		t.Fatal("missing entry must be an error")
	}
	if _, err := digestFromSums([]byte("deadbeef  nft-okboy-linux-386\n"), "nft-okboy-linux-386"); err == nil {
		t.Fatal("a malformed checksum must be an error")
	}
}

// TestCheckDigest: a download that does not hash to the trusted digest fails.
func TestCheckDigest(t *testing.T) {
	if err := checkDigest("f", []byte("binary"), sha("binary")); err != nil {
		t.Fatalf("matching digest rejected: %v", err)
	}
	if err := checkDigest("f", []byte("tampered"), sha("binary")); err == nil {
		t.Fatal("mismatching digest accepted")
	}
}
