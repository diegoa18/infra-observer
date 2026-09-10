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
	concurrency int,
) []PortResult {
	if len(ports) == 0 {
		return nil
	}

	if concurrency <= 0 {
		concurrency = 100
	}

	if concurrency > len(ports) {
		concurrency = len(ports)
	}

	results := make([]PortResult, len(ports))

	jobs := make(chan int)
	var wg sync.WaitGroup

	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for index := range jobs {
				results[index] = scanPort(
					ctx,
					target,
					ports[index],
					timeout,
				)
			}
		}()
	}

dispatch:
	for index := range ports {
		select {
		case <-ctx.Done():
			break dispatch
		case jobs <- index:
		}
	}

	close(jobs)
	wg.Wait()

	for index, result := range results {
		if result.Port == 0 {
			results[index] = PortResult{
				Port:  ports[index],
				State: PortUnknown,
				Error: ctx.Err(),
			}
		}
	}

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

	address := net.JoinHostPort(
		target,
		fmt.Sprintf("%d", port),
	)

	dialer := net.Dialer{
		Timeout: timeout,
	}

	conn, err := dialer.DialContext(
		ctx,
		"tcp",
		address,
	)
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

	defer conn.Close()

	result.State = PortOpen
	return result
}
