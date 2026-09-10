package discovery

import "time"

type Result struct {
	IP        string
	Alive     bool
	Method    string
	RTT       time.Duration
	Reason    string
	Timestamp time.Time
}
