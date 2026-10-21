package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// egressResolveTimeout bounds DNS resolution during egress validation,
// mirroring the 5s resolution timeout in the TypeScript policy engine.
const egressResolveTimeout = 5 * time.Second

// blockedEgressPrefixes mirrors the TypeScript egress policy:
// NetworkRulesPolicy.BLOCKED_EGRESS_CIDRS plus the extra ranges added in
// packages/shared/security-utils/ip-utils.ts (link-local and broadcast).
var blockedEgressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.169.254/32"), // Cloud metadata (IMDS)
	netip.MustParsePrefix("169.254.0.0/16"),     // Link-local IPv4 / generic IMDS
	netip.MustParsePrefix("10.0.0.0/8"),         // RFC1918 private
	netip.MustParsePrefix("172.16.0.0/12"),      // RFC1918 private
	netip.MustParsePrefix("192.168.0.0/16"),     // RFC1918 private
	netip.MustParsePrefix("127.0.0.0/8"),        // Loopback
	netip.MustParsePrefix("0.0.0.0/8"),          // Current network
	netip.MustParsePrefix("255.255.255.255/32"), // Broadcast
	netip.MustParsePrefix("::1/128"),            // IPv6 loopback
	netip.MustParsePrefix("fc00::/7"),           // IPv6 unique local
	netip.MustParsePrefix("fd00::/8"),           // IPv6 unique local
	netip.MustParsePrefix("fe80::/10"),          // IPv6 link-local
}

// IsRestrictedIP reports whether ip falls in a restricted egress range.
// It mirrors isRestrictedIp in the TypeScript ip-utils, with one deliberate
// hardening difference: IPv4-mapped IPv6 forms (e.g. ::ffff:10.0.0.1) are
// unmapped and checked against the IPv4 ranges instead of slipping past
// both families. Unparseable input is not an IP and returns false.
func IsRestrictedIP(ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.WithZone("").Unmap()
	for _, prefix := range blockedEgressPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// IsInternalHostname reports whether hostname names a local or internal
// target, mirroring isInternalHostname in the TypeScript ip-utils.
func IsInternalHostname(hostname string) bool {
	lower := strings.ToLower(hostname)
	return lower == "localhost" ||
		strings.HasSuffix(lower, ".local") ||
		strings.HasSuffix(lower, ".internal") ||
		strings.HasSuffix(lower, ".lan") ||
		strings.HasSuffix(lower, ".home.arpa")
}

// ValidateEgressHost checks one host against the egress policy, mirroring
// NetworkPolicyEngine.validateEgress: direct IPs and internal hostnames are
// classified locally, public hostnames are resolved and every resulting
// address is checked. It fails closed: an unresolvable hostname is an error,
// never a pass.
func ValidateEgressHost(ctx context.Context, hostname string) error {
	if hostname == "" {
		return fmt.Errorf("policy violation: egress target has no host")
	}

	if _, err := netip.ParseAddr(hostname); err == nil {
		if IsRestrictedIP(hostname) {
			return fmt.Errorf("policy violation: direct access to restricted IP %s is prohibited", hostname)
		}
		return nil
	}

	if IsInternalHostname(hostname) {
		return fmt.Errorf("policy violation: access to internal hostname %s is prohibited", hostname)
	}

	ctx, cancel := context.WithTimeout(ctx, egressResolveTimeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip", hostname)
	if err != nil {
		return fmt.Errorf("invalid egress target %s: %w", hostname, err)
	}
	for _, addr := range addrs {
		if IsRestrictedIP(addr.String()) {
			return fmt.Errorf("policy violation: %s resolves to restricted address %s", hostname, addr.String())
		}
	}
	return nil
}
