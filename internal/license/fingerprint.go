package license

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
)

// machineFingerprint generates a stable, platform-independent identifier for
// this host. It is used to loosely bind a license to a machine so the license
// server can detect unusual activity such as sharing one key across many nodes.
//
// The fingerprint is NOT a hard cryptographic lock — its purpose is anomaly
// detection on the server side, not local enforcement.
//
// Resolution order:
//  1. METALWAF_INSTANCE_ID env var  (explicit override — recommended for containers/k8s)
//  2. /etc/machine-id              (Linux/systemd)
//  3. SHA256(stable MACs + OS + hostname)
func machineFingerprint() string {
	// 1. Explicit override — most reliable in containerised environments.
	if id := os.Getenv("METALWAF_INSTANCE_ID"); id != "" {
		return hashShort("explicit:" + id)
	}

	// 2. /etc/machine-id — stable across reboots on systemd Linux hosts.
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			mid := strings.TrimSpace(string(data))
			if mid != "" {
				return hashShort("machine-id:" + mid)
			}
		}
	}

	// 3. Stable MAC addresses + OS + hostname fallback.
	var parts []string
	if h, err := os.Hostname(); err == nil {
		parts = append(parts, "host:"+h)
	}
	parts = append(parts, "os:"+runtime.GOOS)

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		mac := iface.HardwareAddr.String()
		if mac == "" {
			continue
		}
		// Skip loopback and common Docker/virtual bridge MACs (02:42:xx).
		if iface.Flags&net.FlagLoopback != 0 || strings.HasPrefix(mac, "02:42") {
			continue
		}
		if iface.Flags&net.FlagUp != 0 {
			parts = append(parts, "mac:"+mac)
		}
	}
	sort.Strings(parts) // deterministic order
	return hashShort(strings.Join(parts, "|"))
}

// hashShort returns the first 32 hex chars (128 bits) of the SHA-256 of s.
// Long enough to be collision-resistant; short enough to be readable in logs.
func hashShort(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:16])
}

// maskKey returns a safe-to-log representation of a license key, showing only
// the last 4 characters. e.g. "mwaf-****-****-****-A3F9"
func maskKey(key string) string {
	if len(key) <= 4 {
		return "****"
	}
	return strings.Repeat("*", len(key)-4) + key[len(key)-4:]
}
