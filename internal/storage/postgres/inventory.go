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
			`
			SELECT
				id,
				host(ip),
				COALESCE(hostname, ''),
				first_seen,
				last_seen
			FROM assets
			ORDER BY ip
			`,
		)
	} else {
		rows, err = s.pool.Query(
			ctx,
			`
			SELECT
				id,
				host(ip),
				COALESCE(hostname, ''),
				first_seen,
				last_seen
			FROM assets
			WHERE host(ip) = ANY($1::text[])
			ORDER BY ip
			`,
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

	for i := range stored {
		if err := s.loadInventoryPorts(
			ctx,
			stored[i].id,
			&stored[i].asset,
		); err != nil {
			return nil, err
		}
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

func (s *Store) loadInventoryPorts(
	ctx context.Context,
	assetID int64,
	asset *domain.InventoryAsset,
) error {
	rows, err := s.pool.Query(
		ctx,
		`
		SELECT DISTINCT ON (
			po.protocol,
			po.port
		)
			po.port,
			po.protocol,
			po.state,
			o.observed_at,
			COALESCE(s.name, ''),
			COALESCE(s.state, ''),
			COALESCE(s.banner, ''),
			COALESCE(
				s.metadata,
				'{}'::jsonb
			)
		FROM port_observations po
		JOIN observations o
			ON o.id = po.observation_id
		LEFT JOIN LATERAL (
			SELECT
				svc.name,
				svc.state,
				svc.banner,
				svc.metadata
			FROM services svc
			WHERE
				svc.observation_id = o.id
				AND svc.port = po.port
				AND svc.protocol = po.protocol
			ORDER BY svc.id
			LIMIT 1
		) s ON TRUE
		WHERE o.asset_id = $1
		ORDER BY
			po.protocol,
			po.port,
			o.observed_at DESC,
			o.id DESC
		`,
		assetID,
	)
	if err != nil {
		return fmt.Errorf(
			"query inventory ports for asset %d: %w",
			assetID,
			err,
		)
	}
	defer rows.Close()

	for rows.Next() {
		var port domain.InventoryPort

		var serviceName string
		var serviceState string
		var serviceBanner string
		var metadataJSON []byte

		if err := rows.Scan(
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

		asset.Ports = append(
			asset.Ports,
			port,
		)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf(
			"iterate inventory ports for asset %d: %w",
			assetID,
			err,
		)
	}

	sort.Slice(
		asset.Ports,
		func(i, j int) bool {
			if asset.Ports[i].Port ==
				asset.Ports[j].Port {
				return asset.Ports[i].Protocol <
					asset.Ports[j].Protocol
			}

			return asset.Ports[i].Port <
				asset.Ports[j].Port
		},
	)

	return nil
}
