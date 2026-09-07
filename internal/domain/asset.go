package domain

import "time"

type Asset struct {
	IP        string
	Hostname  string
	FirstSeen time.Time
	LastSeen  time.Time
}
