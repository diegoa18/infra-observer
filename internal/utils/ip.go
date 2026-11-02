package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

type TargetInfo struct {
	IP       string
	Hostname string
}

// prohibitedNetworks lists destinations that must never be contacted by a
// scan: cloud instance metadata (IMDS), multicast, and limited broadcast.
// They are parsed once at package initialization and treated as read-only.
var prohibitedNetworks = mustParseCIDRs(
	"169.254.169.254/32",
	"224.0.0.0/4",
	"255.255.255.255/32",
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("utils: invalid prohibited CIDR %q: %v", cidr, err))
		}
		networks = append(networks, network)
	}
	return networks
}

// FilterTargets returns the subset of targets that is neither part of the
// built-in prohibited networks nor covered by any IP/CIDR in excludes.
// Invalid exclude entries are ignored so a single typo does not abort a scan.
func FilterTargets(targets []TargetInfo, excludes []string) []TargetInfo {
	excludedNetworks := parseExcludeNetworks(excludes)
	filtered := make([]TargetInfo, 0, len(targets))

	for _, target := range targets {
		ip := net.ParseIP(target.IP)
		if ip == nil {
			filtered = append(filtered, target)
			continue
		}
		if isProhibitedTarget(ip) || isExcludedTarget(ip, excludedNetworks) {
			continue
		}
		filtered = append(filtered, target)
	}

	return filtered
}

func isProhibitedTarget(ip net.IP) bool {
	for _, network := range prohibitedNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func isExcludedTarget(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseExcludeNetworks(excludes []string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(excludes))

	for _, entry := range excludes {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if ip := net.ParseIP(entry); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			networks = append(networks, &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(bits, bits),
			})
			continue
		}

		if _, network, err := net.ParseCIDR(entry); err == nil {
			networks = append(networks, network)
		}
	}

	return networks
}

func ParseTarget(target string) ([]TargetInfo, error) {
	if target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	if ip := net.ParseIP(target); ip != nil {
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, fmt.Errorf("only IPv4 targets are supported")
		}

		return []TargetInfo{{IP: ipv4.String(), Hostname: ""}}, nil
	}

	if _, network, err := net.ParseCIDR(target); err == nil {
		if network.IP.To4() == nil {
			return nil, fmt.Errorf("only IPv4 CIDR targets are supported")
		}

		return expandIPv4Network(network)
	}

	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve hostname %q: %w",
			target,
			err,
		)
	}

	var result []TargetInfo
	seen := make(map[string]struct{})

	for _, ip := range ips {
		ipv4 := ip.To4()
		if ipv4 == nil {
			continue
		}

		address := ipv4.String()
		if _, exists := seen[address]; exists {
			continue
		}

		seen[address] = struct{}{}
		result = append(result, TargetInfo{
			IP:       address,
			Hostname: target,
		})
	}

	if len(result) == 0 {
		return nil, fmt.Errorf(
			"hostname %q has no IPv4 addresses",
			target,
		)
	}

	return result, nil
}

func expandIPv4Network(network *net.IPNet) ([]TargetInfo, error) {
	ip := network.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 networks are supported")
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("invalid IPv4 network mask")
	}

	if ones < 20 {
		return nil, fmt.Errorf(
			"target network is too large: /%d; maximum supported size is /20",
			ones,
		)
	}

	hostBits := bits - ones
	count := 1 << hostBits

	targets := make([]TargetInfo, 0, count)
	base := binary.BigEndian.Uint32(ip)

	for i := 0; i < count; i++ {
		current := base + uint32(i)
		targetIP := net.IPv4(
			byte(current>>24),
			byte(current>>16),
			byte(current>>8),
			byte(current),
		).String()

		targets = append(targets, TargetInfo{
			IP:       targetIP,
			Hostname: "",
		})
	}

	return targets, nil
}
