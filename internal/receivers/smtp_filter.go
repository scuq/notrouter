package receivers

import (
	"fmt"
	"net/netip"
	"strings"
)

// ipAllowlist holds compiled CIDR matchers. Empty allowlist denies all
// (caller responsibility to reject empty lists at config-validation time).
type ipAllowlist struct {
	prefixes []netip.Prefix
}

func compileIPAllowlist(entries []string) (ipAllowlist, error) {
	out := ipAllowlist{prefixes: make([]netip.Prefix, 0, len(entries))}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}

		// Allow either CIDR (10.0.0.0/8) or bare IP (10.5.5.5).
		// Bare IP gets converted to /32 (or /128 for v6) - matches
		// what most firewall configs accept.
		if !strings.Contains(e, "/") {
			ip, err := netip.ParseAddr(e)
			if err != nil {
				return out, fmt.Errorf("invalid IP %q: %w", e, err)
			}
			bits := 32
			if ip.Is6() {
				bits = 128
			}
			pfx := netip.PrefixFrom(ip, bits)
			out.prefixes = append(out.prefixes, pfx)
			continue
		}
		pfx, err := netip.ParsePrefix(e)
		if err != nil {
			return out, fmt.Errorf("invalid CIDR %q: %w", e, err)
		}
		out.prefixes = append(out.prefixes, pfx)
	}
	return out, nil
}

// allow returns true if the given IP string matches any compiled prefix.
// "unknown" or unparseable IPs always return false.
func (a ipAllowlist) allow(ipStr string) bool {
	if ipStr == "" || ipStr == "unknown" {
		return false
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		// Some sources (Unix sockets, weird proxies) might give us
		// non-IP-looking strings. Treat as not-allowed by default.
		return false
	}
	for _, pfx := range a.prefixes {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// rcptAllowlist matches RCPT TO addresses by lowercased exact match.
// Empty list denies all (caller responsibility at config-validation time).
type rcptAllowlist struct {
	addresses map[string]struct{}
}

func compileRcptAllowlist(entries []string) rcptAllowlist {
	out := rcptAllowlist{addresses: make(map[string]struct{}, len(entries))}
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		out.addresses[e] = struct{}{}
	}
	return out
}

func (a rcptAllowlist) allow(addr string) bool {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" {
		return false
	}
	_, ok := a.addresses[addr]
	return ok
}

// fromAllowlist matches MAIL FROM addresses. Empty list = ACCEPT ANY
// (semantically distinct from rcpt: most setups want to restrict who
// CAN deliver to but don't care about the from address since it's
// trivially spoofable on port 25 anyway). The IP allowlist is the
// real trust boundary.
type fromAllowlist struct {
	addresses    map[string]struct{}
	domainSuffix []string // for "@example.com" entries we wildcard on domain
	allowAny     bool
}

func compileFromAllowlist(entries []string) fromAllowlist {
	if len(entries) == 0 {
		return fromAllowlist{allowAny: true}
	}
	out := fromAllowlist{
		addresses: make(map[string]struct{}),
	}
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		// "@example.com" means "any address ending in @example.com"
		// "user@example.com" means exact match
		if strings.HasPrefix(e, "@") {
			out.domainSuffix = append(out.domainSuffix, e)
			continue
		}
		out.addresses[e] = struct{}{}
	}
	if len(out.addresses) == 0 && len(out.domainSuffix) == 0 {
		// All entries were empty - treat as accept-any (matches the
		// no-config case rather than denying-all on bad config).
		return fromAllowlist{allowAny: true}
	}
	return out
}

func (a fromAllowlist) allow(addr string) bool {
	if a.allowAny {
		return true
	}
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" {
		// Empty MAIL FROM (bounce-style messages, "MAIL FROM:<>")
		// is rejected unless the allowlist explicitly contains "".
		// Most monitoring senders send a real from address.
		_, ok := a.addresses[""]
		return ok
	}
	if _, ok := a.addresses[addr]; ok {
		return true
	}
	for _, suffix := range a.domainSuffix {
		if strings.HasSuffix(addr, suffix) {
			return true
		}
	}
	return false
}

// Helper to format CIDR slice for log lines without exposing the netip
// internals directly. Used in startup banner.
func (a ipAllowlist) String() string {
	parts := make([]string, len(a.prefixes))
	for i, p := range a.prefixes {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}
