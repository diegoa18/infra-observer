package scanner

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestScanPortOpen(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	sem := make(chan struct{}, 10)

	results := ScanPorts(
		context.Background(),
		"127.0.0.1",
		[]int{port},
		time.Second,
		sem,
		nil,
	)

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}

	if results[0].State != PortOpen {
		t.Fatalf("state = %q, want %q", results[0].State, PortOpen)
	}
}

func TestScanPortClosed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	sem := make(chan struct{}, 10)

	results := ScanPorts(
		context.Background(),
		"127.0.0.1",
		[]int{port},
		time.Second,
		sem,
		nil,
	)

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}

	if results[0].State != PortClosed {
		t.Fatalf("state = %q, want %q", results[0].State, PortClosed)
	}
}

func TestScanPortUnknownOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sem := make(chan struct{}, 10)

	results := ScanPorts(
		ctx,
		"127.0.0.1",
		[]int{22, 80, 443},
		time.Second,
		sem,
		nil,
	)

	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	for i, result := range results {
		if result.State != PortUnknown {
			t.Fatalf("results[%d].State = %q, want %q", i, result.State, PortUnknown)
		}
	}
}

func TestScanPortsRateLimiterDelaysAdditionalRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	sem := make(chan struct{}, 2)
	limiter := rate.NewLimiter(10, 1)

	start := time.Now()
	results := ScanPorts(
		ctx,
		"127.0.0.1",
		[]int{1, 2},
		time.Second,
		sem,
		limiter,
	)
	elapsed := time.Since(start)

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if elapsed < 50*time.Millisecond {
		t.Fatalf("scan finished in %v; expected rate limiter to delay it", elapsed)
	}
}
