package domain

import "time"

type DiscoveryEvidence struct {
	Method string
	RTT    time.Duration
	Reason string
}

type Observation struct {
	ObservedAt time.Time
	Asset      Asset
	Discovery  DiscoveryEvidence
	Services   []Service
}
