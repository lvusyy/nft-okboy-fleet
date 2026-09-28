//go:build !unix

package firewall

// ufw only exists on Linux; elsewhere (dev builds) there is nothing to lock.
const ufwLockPath = ""

func lockFile(string) (func(), error) { return func() {}, nil }
