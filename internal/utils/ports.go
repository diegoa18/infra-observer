package utils

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func ParsePortRange(value string) ([]int, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("port list cannot be empty")
	}

	seen := make(map[int]struct{})

	for _, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)

		if token == "" {
			return nil, fmt.Errorf("empty port expression")
		}

		if strings.Contains(token, "-") {
			if err := parsePortRange(token, seen); err != nil {
				return nil, err
			}
			continue
		}

		port, err := strconv.Atoi(token)
		if err != nil {
			return nil, fmt.Errorf(
				"invalid port %q",
				token,
			)
		}

		if !validPort(port) {
			return nil, fmt.Errorf(
				"port out of range: %d",
				port,
			)
		}

		seen[port] = struct{}{}
	}

	ports := make([]int, 0, len(seen))

	for port := range seen {
		ports = append(ports, port)
	}

	sort.Ints(ports)

	return ports, nil
}

func parsePortRange(
	value string,
	seen map[int]struct{},
) error {
	parts := strings.Split(value, "-")

	if len(parts) != 2 {
		return fmt.Errorf(
			"invalid port range %q",
			value,
		)
	}

	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return fmt.Errorf(
			"invalid start port %q",
			parts[0],
		)
	}

	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return fmt.Errorf(
			"invalid end port %q",
			parts[1],
		)
	}

	if !validPort(start) || !validPort(end) {
		return fmt.Errorf(
			"port range out of bounds: %s",
			value,
		)
	}

	if start > end {
		return fmt.Errorf(
			"start port is greater than end port: %s",
			value,
		)
	}

	for port := start; port <= end; port++ {
		seen[port] = struct{}{}
	}

	return nil
}

func validPort(port int) bool {
	return port >= 1 && port <= 65535
}
