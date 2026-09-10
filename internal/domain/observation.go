package domain

import "time"

type DiscoveryEvidence struct {
	Method string
	RTT    time.Duration
	Reason string
}

type PortObservation struct {
	Port     int
	Protocol string
	State    string
}

type Observation struct {
	ObservedAt time.Time
	Asset      Asset
	Discovery  DiscoveryEvidence
	Ports      []PortObservation
	Services   []Service
}
