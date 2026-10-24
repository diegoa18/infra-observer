package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"infra-observer/internal/domain"

	"github.com/jackc/pgx/v5"
)

type storedInventoryAsset struct {
	id    int64
	asset domain.InventoryAsset
}

func (s *Store) Inventory(
	ctx context.Context,
	ips []string,
) ([]domain.InventoryAsset, error) {
	var (
		rows pgx.Rows
		err  error
	)

	if len(ips) == 0 {
		rows, err = s.pool.Query(
			ctx,
			selectAllInventoryAssetsSQL,
		)
	} else {
		rows, err = s.pool.Query(
			ctx,
			selectFilteredInventoryAssetsSQL,
			ips,
		)
	}

	if err != nil {
		return nil, fmt.Errorf(
			"query inventory assets: %w",
			err,
		)
	}

	var stored []storedInventoryAsset

	for rows.Next() {
		var item storedInventoryAsset

		if err := rows.Scan(
			&item.id,
			&item.asset.Asset.IP,
			&item.asset.Asset.Hostname,
			&item.asset.FirstSeen,
			&item.asset.LastSeen,
		); err != nil {
			rows.Close()

			return nil, fmt.Errorf(
				"scan inventory asset: %w",
				err,
			)
		}

		stored = append(
			stored,
			item,
		)
	}

	if err := rows.Err(); err != nil {
		rows.Close()

		return nil, fmt.Errorf(
			"iterate inventory assets: %w",
			err,
		)
	}

	rows.Close()

	if len(stored) == 0 {
		return nil, nil
	}

	assetIDs := make([]int64, len(stored))
	indexByAssetID := make(map[int64]int, len(stored))

	for i, item := range stored {
		assetIDs[i] = item.id
		indexByAssetID[item.id] = i
	}

	if err := s.loadInventoryPortsBulk(
		ctx,
		assetIDs,
		indexByAssetID,
		stored,
	); err != nil {
		return nil, err
	}

	inventory := make(
		[]domain.InventoryAsset,
		len(stored),
	)

	for i := range stored {
		inventory[i] = stored[i].asset
	}

	return inventory, nil
}

func (s *Store) loadInventoryPortsBulk(
	ctx context.Context,
	assetIDs []int64,
	indexByAssetID map[int64]int,
	stored []storedInventoryAsset,
) error {
	rows, err := s.pool.Query(
		ctx,
		selectInventoryPortsByAssetsSQL,
		assetIDs,
	)
	if err != nil {
		return fmt.Errorf(
			"query bulk inventory ports: %w",
			err,
		)
	}
	defer rows.Close()

	for rows.Next() {
		var assetID int64
		var port domain.InventoryPort

		var serviceName string
		var serviceState string
		var serviceBanner string
		var metadataJSON []byte

		if err := rows.Scan(
			&assetID,
			&port.Port,
			&port.Protocol,
			&port.State,
			&port.LastObservedAt,
			&serviceName,
			&serviceState,
			&serviceBanner,
			&metadataJSON,
		); err != nil {
			return fmt.Errorf(
				"scan inventory port for asset %d: %w",
				assetID,
				err,
			)
		}

		if serviceName != "" {
			metadata := make(
				map[string]string,
			)

			if len(metadataJSON) > 0 {
				if err := json.Unmarshal(
					metadataJSON,
					&metadata,
				); err != nil {
					return fmt.Errorf(
						"decode inventory service metadata for asset %d port %d: %w",
						assetID,
						port.Port,
						err,
					)
				}
			}

			port.Service = &domain.Service{
				Port:     port.Port,
				Protocol: port.Protocol,
				Name:     serviceName,
				State: domain.ServiceState(
					serviceState,
				),
				Banner:   serviceBanner,
				Metadata: metadata,
			}
		}

		if idx, exists := indexByAssetID[assetID]; exists {
			stored[idx].asset.Ports = append(
				stored[idx].asset.Ports,
				port,
			)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf(
			"iterate bulk inventory ports: %w",
			err,
		)
	}

	for i := range stored {
		ports := stored[i].asset.Ports
		sort.Slice(
			ports,
			func(a, b int) bool {
				if ports[a].Port == ports[b].Port {
					return ports[a].Protocol < ports[b].Protocol
				}

				return ports[a].Port < ports[b].Port
			},
		)
	}

	return nil
}
