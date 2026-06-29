package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// upgradeRepo is the GitHub repo whose Releases host the prebuilt binaries.
const upgradeRepo = "lvusyy/nft-okboy-fleet"

// ghMirrors are tried in order for every GitHub download so the upgrade works
// from networks where github.com is slow/blocked. "" is the direct path; the
// rest are public CN-friendly reverse proxies (see ghproxy.link for live ones).
var ghMirrors = []string{"", "https://ghfast.top/", "https://gh-proxy.com/"}

// CmdUpgrade self-updates the running okboy binary to the latest GitHub release
// (or a pinned --version). It is the day-2 counterpart of deploy/install.sh:
//
//  1. resolve the target tag (latest release, or --version);
//  2. back up the DB first — a newer binary may migrate the schema forward, so a
//     rollback needs the pre-upgrade copy;
//  3. download the release asset + its .sha256 (mirror fallback) and verify;
//  4. atomically swap the running binary, keeping <exe>.bak;
//  5. health-check the new binary and roll back on failure;
//  6. restart the systemd service (best-effort, only if managed by systemd).
//
// Only linux/amd64 has published binaries; other platforms must build from source.
func CmdUpgrade(cfgPath, version string, args []string) error {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	check := fs.Bool("check", false, "Only report whether a newer release exists; do not install")
	target := fs.String("version", "", "Install this exact tag (e.g. v0.2.0) instead of the latest")
	noRestart := fs.Bool("no-restart", false, "Do not restart the service after upgrading")
	noBackup := fs.Bool("no-backup", false, "Skip the DB backup (use on agent nodes, which hold no DB)")
	service := fs.String("service", "okboy", "systemd unit to restart after upgrade (use okboy-agent on an agent node)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	asset := assetForHost()
	if asset == "" {
		return fmt.Errorf("no prebuilt binary for %s/%s; build from source (32-bit ARM: use deploy/install.sh)",
			runtime.GOOS, runtime.GOARCH)
	}

	want := *target
	if want == "" {
		latest, err := latestReleaseTag(upgradeRepo)
		if err != nil {
			return fmt.Errorf("resolve latest release: %w (or pass --version vX.Y.Z)", err)
		}
		want = latest
	}
	fmt.Printf("Current: %s   Target: %s\n", displayVersion(version), want)

	if *check {
		if sameVersion(version, want) {
			fmt.Println("Already up to date.")
		} else {
			fmt.Printf("A newer release is available: %s\n", want)
		}
		return nil
	}
	if *target == "" && sameVersion(version, want) {
		fmt.Println("Already up to date.")
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("upgrade must run as root (try: sudo okboy upgrade)")
	}

	// Resolve symlinks so the staged binary lands in the same directory as the
	// real file — os.Rename is only atomic within one filesystem.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate self: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}

	// DB backup before any swap (rollback safety for forward migrations). Reuses
	// CmdBackup so retention/checksum behave identically to a manual backup. Agent
	// nodes hold no DB, so --no-backup skips this (and avoids creating an empty one).
	if !*noBackup {
		fmt.Println("Backing up database…")
		if berr := CmdBackup(cfgPath, nil); berr != nil {
			fmt.Fprintf(os.Stderr, "warning: db backup failed (continuing): %v\n", berr)
		}
	}

	fmt.Printf("Downloading %s %s…\n", asset, want)
	data, err := ghDownload(upgradeRepo, want, asset)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if verr := verifyChecksum(upgradeRepo, want, asset, data); verr != nil {
		return verr
	}

	// Stage in the target directory, then atomically swap, keeping a .bak.
	dir := filepath.Dir(exe)
	tmp := filepath.Join(dir, ".okboy.upgrade.tmp")
	if werr := os.WriteFile(tmp, data, 0o755); werr != nil {
		return fmt.Errorf("write staged binary: %w", werr)
	}
	defer os.Remove(tmp) // no-op once the rename below succeeds

	bak := exe + ".bak"
	if cerr := copyFile(exe, bak, 0o755); cerr != nil {
		return fmt.Errorf("back up current binary: %w", cerr)
	}
	if rerr := os.Rename(tmp, exe); rerr != nil {
		return fmt.Errorf("install new binary: %w", rerr)
	}

	// Sanity-check the freshly installed binary runs at all (catches a corrupt or
	// wrong-arch download) before touching the service; restore the .bak on failure.
	if out, herr := exec.Command(exe, "--version").CombinedOutput(); herr != nil {
		_ = os.Rename(bak, exe)
		return fmt.Errorf("new binary failed to run (%v: %s); rolled back",
			herr, strings.TrimSpace(string(out)))
	}

	if !*noRestart {
		if rerr := restartService(*service); rerr != nil {
			// Not systemd-managed (dev / manual run): the new binary is staged, but
			// starting it is the operator's job — nothing to verify or roll back.
			fmt.Fprintf(os.Stderr, "warning: could not restart service (start it manually): %v\n", rerr)
		} else if !serviceHealthy(*service, 10*time.Second) {
			// The service restarted but never reached active — e.g. the new binary
			// crashes on start. A bare `--version` check (above) cannot catch that,
			// so verify the live service and roll back to the previous binary.
			_ = os.Rename(bak, exe)
			_ = exec.Command("systemctl", "restart", *service).Run()
			return fmt.Errorf("upgraded binary did not bring %q up; rolled back to the previous version", *service)
		} else {
			fmt.Printf("Service %q restarted and healthy.\n", *service)
		}
	}

	fmt.Printf("Upgraded okboy %s → %s.  Previous binary kept at %s\n",
		displayVersion(version), want, bak)
	return nil
}

// displayVersion renders the build version for display (a leading "v" for a real
// semver, or "dev" unchanged).
func displayVersion(v string) string {
	if v == "" || v == "dev" {
		return "dev"
	}
	return "v" + strings.TrimPrefix(v, "v")
}

// sameVersion reports whether the build version already matches tag (ignoring a
// leading "v"). A "dev" build is never considered up to date.
func sameVersion(version, tag string) bool {
	if version == "" || version == "dev" {
		return false
	}
	return strings.TrimPrefix(version, "v") == strings.TrimPrefix(tag, "v")
}

// httpClient is the client for the small GitHub API call (latest-release lookup).
// Short connect / response-header timeouts make it fail FAST to the caller's
// fallback when api.github.com is unreachable, instead of stalling ~90s.
func httpClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 8 * time.Second}).DialContext,
			TLSHandshakeTimeout:   8 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
		},
	}
}

// latestReleaseTag resolves the newest release tag via the GitHub API.
func latestReleaseTag(repo string) (string, error) {
	req, err := http.NewRequest(http.MethodGet,
		"https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "okboy-upgrade")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api returned %d", resp.StatusCode)
	}
	var r struct {
		TagName string `json:"tag_name"`
	}
	if derr := json.NewDecoder(resp.Body).Decode(&r); derr != nil {
		return "", derr
	}
	if r.TagName == "" {
		return "", fmt.Errorf("empty tag_name in release response")
	}
	return r.TagName, nil
}

// ghDownload fetches a release asset, trying each mirror prefix until one serves
// HTTP 200.
func ghDownload(repo, tag, asset string) ([]byte, error) {
	path := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repo, tag, asset)
	var lastErr error
	for _, m := range ghMirrors {
		b, err := ghGet(m + path)
		if err != nil {
			lastErr = err
			continue
		}
		return b, nil
	}
	return nil, lastErr
}

// ghGet downloads url with a stall watchdog: a short connect timeout plus a 20s
// no-progress abort. The GitHub release CDN can connect, return 200, then reset
// mid-transfer; a client with only a total timeout would wait that out before the
// caller fails over to a mirror, making `upgrade` slow on networks where the direct
// path is blackholed. Resetting the watchdog on every chunk lets a genuinely slow-
// but-progressing download continue up to the hard cap.
func ghGet(url string) ([]byte, error) {
	const (
		connectTimeout = 8 * time.Second
		stallTimeout   = 15 * time.Second // abort if NO byte arrives for this long
		minSpeed       = 50 * 1024        // B/s; sustained slower = a blocked/stalled path, not a slow link
		speedGrace     = 10 * time.Second // give the transfer this long before judging its speed
		hardCap        = 8 * time.Minute
	)
	ctx, cancel := context.WithTimeout(context.Background(), hardCap)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: connectTimeout}).DialContext,
		TLSHandshakeTimeout:   connectTimeout,
		ResponseHeaderTimeout: stallTimeout,
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s → HTTP %d", url, resp.StatusCode)
	}
	watchdog := time.AfterFunc(stallTimeout, cancel) // fires if a read stalls (no data)
	defer watchdog.Stop()
	var buf bytes.Buffer
	chunk := make([]byte, 64*1024)
	start := time.Now()
	for {
		n, rerr := resp.Body.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			watchdog.Reset(stallTimeout)
			// A blocked/reset CDN path can dribble bytes slowly, keeping the no-data
			// watchdog alive forever; fail over once the average rate proves too low
			// to be a real (if slow) link. Matches install.sh's curl --speed-time.
			if el := time.Since(start); el > speedGrace && float64(buf.Len())/el.Seconds() < minSpeed {
				return nil, fmt.Errorf("%s → throughput below %d B/s, failing over", url, minSpeed)
			}
		}
		if rerr == io.EOF {
			return buf.Bytes(), nil
		}
		if rerr != nil {
			return nil, rerr
		}
	}
}

// assetForHost maps the running platform to its published release asset name, or
// "" when no prebuilt binary is published for it. The release ships one static
// binary per linux arch named "nft-okboy-linux-<arch>".
func assetForHost() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	switch runtime.GOARCH {
	case "amd64", "arm64", "386", "loong64", "ppc64le", "riscv64", "s390x":
		return "okboy-linux-" + runtime.GOARCH
	default:
		// "arm" cannot be disambiguated into armv6/armv7 at runtime — deploy/
		// install.sh resolves that from `uname -m`.
		return ""
	}
}

// verifyChecksum downloads the release's combined SHA256SUMS file and checks data
// against the line for asset. A missing SHA256SUMS is a warning, not a hard fail.
func verifyChecksum(repo, tag, asset string, data []byte) error {
	sums, err := ghDownload(repo, tag, "SHA256SUMS")
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: no published SHA256SUMS; skipping verification")
		return nil
	}
	want := ""
	for _, line := range strings.Split(string(sums), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[1] == asset { // "<hex>  <file>"
			want = f[0]
			break
		}
	}
	if want == "" {
		return fmt.Errorf("SHA256SUMS has no entry for %s — aborting", asset)
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(want, hex.EncodeToString(sum[:])) {
		return fmt.Errorf("checksum mismatch for %s — aborting", asset)
	}
	fmt.Println("Checksum verified.")
	return nil
}

// copyFile copies src to dst with the given mode (used for the rollback .bak).
func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, mode)
}

// serviceHealthy reports whether the unit is genuinely up after a restart, not just
// momentarily "active". A Type=simple service is reported "active" for the brief
// instant between each restart spawn and its crash, so any check that returns on the
// first "active" reading false-positives on a crash-loop — exactly how a serve-panic
// could slip past the upgrade health gate. Instead let the service settle, then
// require BOTH that systemd did not auto-restart it during the window (NRestarts
// stable) AND that it ends in the active state.
func serviceHealthy(name string, settle time.Duration) bool {
	n0 := unitProp(name, "NRestarts")
	time.Sleep(settle)
	if unitProp(name, "NRestarts") != n0 {
		return false // auto-restarted during the window → crash-looping
	}
	return unitProp(name, "ActiveState") == "active"
}

// unitProp returns a single systemd unit property value, or "" on error.
func unitProp(name, prop string) string {
	out, _ := exec.Command("systemctl", "show", name, "-p", prop, "--value").Output()
	return strings.TrimSpace(string(out))
}

// restartService restarts a systemd unit, but only when systemd actually manages
// it — on a non-systemd or dev host this returns an error the caller downgrades
// to a warning instead of failing the whole upgrade.
func restartService(name string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not found")
	}
	if err := exec.Command("systemctl", "is-enabled", name).Run(); err != nil {
		return fmt.Errorf("service %q not managed by systemd", name)
	}
	return exec.Command("systemctl", "restart", name).Run()
}
