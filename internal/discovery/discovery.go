package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func DiscoverHost(
	ctx context.Context,
	target string,
	timeout time.Duration,
) (Result, error) {
	result := Result{
		IP:        target,
		Method:    "icmp",
		Timestamp: time.Now(),
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		result.Reason = "socket-error"
		return result, fmt.Errorf("open ICMP socket: %w", err)
	}
	defer conn.Close()

	dst, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		result.Reason = "resolve-error"
		return result, fmt.Errorf("resolve target %q: %w", target, err)
	}

	message := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("INFRA-OBSERVER"),
		},
	}

	payload, err := message.Marshal(nil)
	if err != nil {
		result.Reason = "marshal-error"
		return result, fmt.Errorf("marshal ICMP request: %w", err)
	}

	start := time.Now()

	if _, err := conn.WriteTo(payload, dst); err != nil {
		result.Reason = "send-error"
		return result, fmt.Errorf("send ICMP request: %w", err)
	}

	deadline := time.Now().Add(timeout)

	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	if err := conn.SetReadDeadline(deadline); err != nil {
		result.Reason = "deadline-error"
		return result, fmt.Errorf("set ICMP deadline: %w", err)
	}

	buffer := make([]byte, 1500)

	for {
		if err := ctx.Err(); err != nil {
			result.Reason = "context-canceled"
			return result, err
		}

		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				result.Reason = "context-canceled"
				return result, ctx.Err()
			}

			result.Reason = "timeout"
			return result, nil
		}

		if peer.String() != dst.String() {
			continue
		}

		reply, err := icmp.ParseMessage(
			ipv4.ICMPTypeEchoReply.Protocol(),
			buffer[:n],
		)
		if err != nil {
			continue
		}

		if reply.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		result.Alive = true
		result.RTT = time.Since(start)
		result.Reason = "echo-reply"

		return result, nil
	}
}

func DiscoverHostTCP(
	ctx context.Context,
	target string,
	timeout time.Duration,
) (Result, error) {
	result := Result{
		IP:        target,
		Method:    "tcp-connect",
		Timestamp: time.Now(),
	}

	for _, port := range []int{80, 443} {
		if err := ctx.Err(); err != nil {
			result.Reason = "context-canceled"
			return result, err
		}

		address := net.JoinHostPort(
			target,
			fmt.Sprintf("%d", port),
		)

		dialer := net.Dialer{
			Timeout: timeout,
		}

		start := time.Now()

		conn, err := dialer.DialContext(
			ctx,
			"tcp",
			address,
		)
		if err == nil {
			conn.Close()

			result.Alive = true
			result.RTT = time.Since(start)
			result.Reason = fmt.Sprintf(
				"connection-established port-%d",
				port,
			)

			return result, nil
		}

		if isConnectionRefused(err) {
			result.Alive = true
			result.RTT = time.Since(start)
			result.Reason = fmt.Sprintf(
				"connection-refused port-%d",
				port,
			)

			return result, nil
		}
	}

	result.Reason = "no-response"
	return result, nil
}

func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
