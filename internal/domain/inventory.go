package domain

import "time"

type InventoryPort struct {
	Port           int
	Protocol       string
	State          string
	LastObservedAt time.Time
	Service        *Service
}

type InventoryAsset struct {
	Asset     Asset
	FirstSeen time.Time
	LastSeen  time.Time
	Ports     []InventoryPort
}
