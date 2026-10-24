package domain

import "context"

type Repository interface {
	SaveObservation(ctx context.Context, observation Observation) error
	LatestObservations(ctx context.Context, ip string, limit int) ([]Observation, error)
	Inventory(ctx context.Context, ips []string) ([]InventoryAsset, error)
	Close()
}
