package utils

import (
	"encoding/binary"
	"fmt"
	"net"
)

func ParseTarget(target string) ([]string, error) {
	if target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	if ip := net.ParseIP(target); ip != nil {
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, fmt.Errorf("only IPv4 targets are supported")
		}

		return []string{ipv4.String()}, nil
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

	var result []string

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
		result = append(result, address)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf(
			"hostname %q has no IPv4 addresses",
			target,
		)
	}

	return result, nil
}

func expandIPv4Network(network *net.IPNet) ([]string, error) {
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

	targets := make([]string, 0, count)

	base := binary.BigEndian.Uint32(ip)

	for i := 0; i < count; i++ {
		current := base + uint32(i)

		target := net.IPv4(
			byte(current>>24),
			byte(current>>16),
			byte(current>>8),
			byte(current),
		).String()

		targets = append(targets, target)
	}

	return targets, nil
}

func incrementIPv4(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}
