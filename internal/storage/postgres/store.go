package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"infra-observer/internal/domain"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func Open(
	ctx context.Context,
	databaseURL string,
) (*Store, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("database URL cannot be empty")
	}

	pool, err := pgxpool.New(
		ctx,
		databaseURL,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create PostgreSQL pool: %w",
			err,
		)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()

		return nil, fmt.Errorf(
			"connect to PostgreSQL: %w",
			err,
		)
	}

	return &Store{
		pool: pool,
	}, nil
}

func (s *Store) Close() {
	if s == nil || s.pool == nil {
		return
	}

	s.pool.Close()
}

func (s *Store) SaveObservation(
	ctx context.Context,
	observation domain.Observation,
) error {
	tx, err := s.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return fmt.Errorf(
			"begin observation transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	var assetID int64

	err = tx.QueryRow(
		ctx,
		`
		INSERT INTO assets (
			ip,
			hostname,
			first_seen,
			last_seen
		)
		VALUES (
			$1,
			NULLIF($2, ''),
			$3,
			$3
		)
		ON CONFLICT (ip)
		DO UPDATE SET
			hostname = COALESCE(
				NULLIF(EXCLUDED.hostname, ''),
				assets.hostname
			),
			last_seen = GREATEST(
				assets.last_seen,
				EXCLUDED.last_seen
			)
		RETURNING id
		`,
		observation.Asset.IP,
		observation.Asset.Hostname,
		observation.ObservedAt,
	).Scan(&assetID)
	if err != nil {
		return fmt.Errorf(
			"upsert asset %s: %w",
			observation.Asset.IP,
			err,
		)
	}

	var observationID int64

	err = tx.QueryRow(
		ctx,
		`
		INSERT INTO observations (
			asset_id,
			observed_at,
			discovery_method,
			discovery_rtt_ns,
			discovery_reason
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			$5
		)
		RETURNING id
		`,
		assetID,
		observation.ObservedAt,
		observation.Discovery.Method,
		int64(observation.Discovery.RTT),
		observation.Discovery.Reason,
	).Scan(&observationID)
	if err != nil {
		return fmt.Errorf(
			"insert observation for %s: %w",
			observation.Asset.IP,
			err,
		)
	}

	for _, port := range observation.Ports {
		_, err := tx.Exec(
			ctx,
			`
			INSERT INTO port_observations (
				observation_id,
				port,
				protocol,
				state
			)
			VALUES (
				$1,
				$2,
				$3,
				$4
			)
			`,
			observationID,
			port.Port,
			port.Protocol,
			port.State,
		)
		if err != nil {
			return fmt.Errorf(
				"insert port %d/%s for %s: %w",
				port.Port,
				port.Protocol,
				observation.Asset.IP,
				err,
			)
		}
	}

	for _, service := range observation.Services {
		metadata := service.Metadata
		if metadata == nil {
			metadata = map[string]string{}
		}

		metadataJSON, err := json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf(
				"encode metadata for port %d/%s: %w",
				service.Port,
				service.Protocol,
				err,
			)
		}

		_, err = tx.Exec(
			ctx,
			`
			INSERT INTO services (
				observation_id,
				port,
				protocol,
				name,
				state,
				banner,
				metadata
			)
			VALUES (
				$1,
				$2,
				$3,
				$4,
				$5,
				$6,
				$7::jsonb
			)
			`,
			observationID,
			service.Port,
			service.Protocol,
			service.Name,
			string(service.State),
			service.Banner,
			string(metadataJSON),
		)
		if err != nil {
			return fmt.Errorf(
				"insert service %d/%s for %s: %w",
				service.Port,
				service.Protocol,
				observation.Asset.IP,
				err,
			)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit observation for %s: %w",
			observation.Asset.IP,
			err,
		)
	}

	return nil
}
