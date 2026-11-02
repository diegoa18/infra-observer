package detection

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestProbeHTTPSanitizesHeaderValues(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		fmt.Fprint(conn, "HTTP/1.1 200 OK\r\n"+
			"Server: evil\tred\r\n"+
			"X-Powered-By: PHP\t8.2\r\n"+
			"Content-Length: 0\r\n"+
			"Connection: close\r\n"+
			"\r\n")
	}()

	host, portValue, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("net.SplitHostPort() error = %v", err)
	}
	port, err := strconv.Atoi(portValue)
	if err != nil {
		t.Fatalf("strconv.Atoi() error = %v", err)
	}

	result, err := ProbeHTTP(context.Background(), host, "", port, time.Second)
	if err != nil {
		t.Fatalf("ProbeHTTP() error = %v", err)
	}

	if result.Server != "evil red" {
		t.Fatalf("Server = %q, want %q", result.Server, "evil red")
	}
	if result.PoweredBy != "PHP 8.2" {
		t.Fatalf("PoweredBy = %q, want %q", result.PoweredBy, "PHP 8.2")
	}
}
