//go:build unix

package firewall

import (
	"os"
	"syscall"
)

// ufwLockPath is the host-wide lock serializing ufw changes between nft-okboy
// processes (the server, CLI commands, an agent) — see UfwBackend.lock.
const ufwLockPath = "/run/nft-okboy.ufw.lock"

// lockFile takes an exclusive flock on path and returns the release func.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
