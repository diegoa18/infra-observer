package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

type PortState string

const (
	PortOpen    PortState = "open"
	PortClosed  PortState = "closed"
	PortUnknown PortState = "unknown"
)

type PortResult struct {
	Port  int
	State PortState
	Error error
}

func ScanPorts(
	ctx context.Context,
	target string,
	ports []int,
	timeout time.Duration,
	sem chan struct{},
) []PortResult {
	if len(ports) == 0 {
		return nil
	}

	results := make([]PortResult, len(ports))
	var wg sync.WaitGroup

	for i, p := range ports {
		wg.Add(1)

		go func(index, port int) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				results[index] = PortResult{
					Port:  port,
					State: PortUnknown,
					Error: ctx.Err(),
				}
				return
			case sem <- struct{}{}:
			}

			results[index] = scanPort(ctx, target, port, timeout)
			<-sem
		}(i, p)
	}

	wg.Wait()
	return results
}

func scanPort(
	ctx context.Context,
	target string,
	port int,
	timeout time.Duration,
) PortResult {
	result := PortResult{
		Port:  port,
		State: PortUnknown,
	}

	address := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	dialer := net.Dialer{Timeout: timeout}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		if ctx.Err() != nil {
			result.Error = ctx.Err()
			return result
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			result.State = PortClosed
			result.Error = err
			return result
		}
		result.Error = err
		return result
	}

	conn.Close()
	result.State = PortOpen
	return result
}
