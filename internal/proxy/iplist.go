package proxy

import (
	"net"
	"strings"

	"github.com/metalwaf/metalwaf/internal/database"
)

// IPChecker holds compiled allow and block lists (CIDRs + exact IPs).
// Check returns (allowed, blocked):
//   - allowed = true → entry is explicitly allowlisted (skip WAF + rate-limit)
//   - blocked = true → entry is explicitly blocklisted (return 403)
//
// Allowlist is checked before blocklist; a match in either terminates evaluation.
type IPChecker struct {
	allowNets []*net.IPNet
	allowIPs  map[string]bool
	blockNets []*net.IPNet
	blockIPs  map[string]bool
}

// BuildIPChecker compiles a slice of database.IPList entries into an IPChecker.
// Entries with type="allow" build the allowlist; type="block" build the blocklist.
// Invalid CIDRs/IPs are silently skipped.
func BuildIPChecker(lists []*database.IPList) *IPChecker {
	c := &IPChecker{
		allowIPs: make(map[string]bool),
		blockIPs: make(map[string]bool),
	}
	for _, entry := range lists {
		// Try parsing as CIDR first; fall back to plain IP.
		if strings.Contains(entry.CIDR, "/") {
			_, network, err := net.ParseCIDR(entry.CIDR)
			if err != nil {
				continue
			}
			if entry.Type == "allow" {
				c.allowNets = append(c.allowNets, network)
			} else {
				c.blockNets = append(c.blockNets, network)
			}
		} else {
			ip := net.ParseIP(entry.CIDR)
			if ip == nil {
				continue
			}
			normalized := ip.String()
			if entry.Type == "allow" {
				c.allowIPs[normalized] = true
			} else {
				c.blockIPs[normalized] = true
			}
		}
	}
	return c
}

// Check evaluates a raw client IP string (may include port) against the lists.
func (c *IPChecker) Check(rawIP string) (allowed, blocked bool) {
	// Strip port if present.
	host := rawIP
	if h, _, err := net.SplitHostPort(rawIP); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false, false
	}

	// Check allowlist first.
	if c.allowIPs[ip.String()] {
		return true, false
	}
	for _, network := range c.allowNets {
		if network.Contains(ip) {
			return true, false
		}
	}

	// Check blocklist.
	if c.blockIPs[ip.String()] {
		return false, true
	}
	for _, network := range c.blockNets {
		if network.Contains(ip) {
			return false, true
		}
	}

	return false, false
}
