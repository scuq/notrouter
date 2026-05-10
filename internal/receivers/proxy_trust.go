package receivers

import (
	"net"
	"strings"
)

// proxyTrust holds the compiled CIDR list of trusted reverse proxies
// for a webhook receiver. Used to safely extract the real client IP
// from X-Forwarded-For when notrouter is behind a proxy.
//
// SECURITY: never trust XFF unconditionally. Anyone can SET the header
// before reaching your proxy, so trusting it on direct (non-proxied)
// connections lets attackers spoof origin_id. This struct enforces the
// "only trust XFF when the immediate peer is in trusted_proxies" rule.
type proxyTrust struct {
	nets []*net.IPNet
}

// compileTrustedProxies turns CIDR strings into a proxyTrust. Returns
// nil (which all helpers treat as "no trust configured, ignore XFF")
// when the list is empty.
func compileTrustedProxies(cidrs []string) (*proxyTrust, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	pt := &proxyTrust{nets: make([]*net.IPNet, 0, len(cidrs))}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// Support bare IPs as /32 or /128 for convenience.
		if !strings.Contains(c, "/") {
			ip := net.ParseIP(c)
			if ip == nil {
				return nil, &net.ParseError{Type: "trusted_proxies entry", Text: c}
			}
			if ip.To4() != nil {
				c = c + "/32"
			} else {
				c = c + "/128"
			}
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		pt.nets = append(pt.nets, n)
	}
	return pt, nil
}

// isTrusted reports whether the given IP is in any of the configured
// trusted_proxies CIDRs.
func (p *proxyTrust) isTrusted(ip net.IP) bool {
	if p == nil || ip == nil {
		return false
	}
	for _, n := range p.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// extractClientIP returns the best-guess real client IP given:
//   - remoteAddr: the raw http.Request.RemoteAddr ("ip:port")
//   - xff: the raw X-Forwarded-For header value (comma-separated)
//
// Logic:
//   1. Parse remoteAddr to its IP. If trust list is empty OR remote is
//      NOT trusted, return the remote IP - ignore XFF (prevents spoofing
//      on direct connections).
//   2. If remote IS trusted, walk XFF right-to-left, returning the first
//      IP that is NOT itself in trusted_proxies. That's the real client.
//   3. If XFF is missing/malformed when expected (remote is trusted),
//      return remoteIP and let the caller log a warning.
//
// Returns (ip-as-string, missingXFF-bool). The bool is true ONLY when
// the caller's RemoteAddr was trusted but XFF was empty/unusable - the
// caller should log a misconfiguration warning in that case.
func (p *proxyTrust) extractClientIP(remoteAddr, xff string) (string, bool) {
	remoteIPStr := stripPort(remoteAddr)
	remoteIP := net.ParseIP(remoteIPStr)

	// No trust config or untrusted peer: use raw remote, never XFF.
	if !p.isTrusted(remoteIP) {
		return remoteIPStr, false
	}

	// Peer is trusted - walk XFF right to left.
	if xff == "" {
		// Trusted peer but no XFF header - misconfigured proxy.
		// Caller should log a warning.
		return remoteIPStr, true
	}

	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(parts[i])
		if hop == "" {
			continue
		}
		ip := net.ParseIP(hop)
		if ip == nil {
			continue // skip malformed entries (e.g. "unknown")
		}
		if !p.isTrusted(ip) {
			return hop, false // first untrusted hop = real client
		}
	}

	// All XFF entries were themselves trusted proxies - probably means
	// a misconfigured proxy chain (everything's a proxy, no real client
	// visible). Fall back to remote.
	return remoteIPStr, true
}

// stripPort removes :port from "ip:port", returning just the IP. Safe
// for IPv6 brackets too. Returns input unchanged if no port present.
func stripPort(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}
