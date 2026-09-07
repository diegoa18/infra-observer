package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"go-scanner/internal/domain"
)

func ScanPorts(
	ctx context.Context,
	target string,
	ports []int,
	timeout time.Duration,
	concurrency int,
) []domain.PortResult {
	if len(ports) == 0 {
		return nil
	}

	if concurrency <= 0 {
		concurrency = 100
	}

	if concurrency > len(ports) {
		concurrency = len(ports)
	}

	results := make([]domain.PortResult, len(ports))

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

	for index := range ports {
		select {
		case <-ctx.Done():
			results[index] = domain.PortResult{
				Port:  ports[index],
				State: domain.PortUnknown,
				Error: ctx.Err(),
			}

		case jobs <- index:
		}
	}

	close(jobs)
	wg.Wait()

	return results
}

func scanPort(
	ctx context.Context,
	target string,
	port int,
	timeout time.Duration,
) domain.PortResult {
	result := domain.PortResult{
		Port:  port,
		State: domain.PortUnknown,
	}

	if err := ctx.Err(); err != nil {
		result.Error = err
		return result
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
	if err == nil {
		conn.Close()

		result.State = domain.PortOpen
		return result
	}

	if ctx.Err() != nil {
		result.Error = ctx.Err()
		return result
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		result.State = domain.PortClosed
		return result
	}

	return result
}
