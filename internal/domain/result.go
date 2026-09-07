package domain

import "time"

type DiscoveryResult struct {
	IP        string
	Alive     bool
	Method    string
	RTT       time.Duration
	Reason    string
	Timestamp time.Time
}

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
