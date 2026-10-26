package utils

import (
	"encoding/binary"
	"fmt"
	"net"
)

type TargetInfo struct {
	IP       string
	Hostname string
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
