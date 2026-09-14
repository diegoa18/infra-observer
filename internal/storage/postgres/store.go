package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

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

func (s *Store) LatestObservations(
	ctx context.Context,
	ip string,
	limit int,
) ([]domain.Observation, error) {
	if limit <= 0 {
		return nil, fmt.Errorf(
			"observation limit must be greater than zero",
		)
	}

	rows, err := s.pool.Query(
		ctx,
		`
		SELECT
			o.id,
			host(a.ip),
			COALESCE(a.hostname, ''),
			o.observed_at,
			o.discovery_method,
			o.discovery_rtt_ns,
			o.discovery_reason
		FROM observations o
		JOIN assets a
			ON a.id = o.asset_id
		WHERE a.ip = $1::inet
		ORDER BY
			o.observed_at DESC,
			o.id DESC
		LIMIT $2
		`,
		ip,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"query latest observations for %s: %w",
			ip,
			err,
		)
	}
	defer rows.Close()

	type storedObservation struct {
		id          int64
		observation domain.Observation
	}

	var stored []storedObservation

	for rows.Next() {
		var item storedObservation
		var discoveryRTT int64

		err := rows.Scan(
			&item.id,
			&item.observation.Asset.IP,
			&item.observation.Asset.Hostname,
			&item.observation.ObservedAt,
			&item.observation.Discovery.Method,
			&discoveryRTT,
			&item.observation.Discovery.Reason,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"scan observation for %s: %w",
				ip,
				err,
			)
		}

		item.observation.Discovery.RTT =
			timeDuration(discoveryRTT)

		stored = append(
			stored,
			item,
		)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate observations for %s: %w",
			ip,
			err,
		)
	}

	for i := range stored {
		if err := s.loadPorts(
			ctx,
			stored[i].id,
			&stored[i].observation,
		); err != nil {
			return nil, err
		}

		if err := s.loadServices(
			ctx,
			stored[i].id,
			&stored[i].observation,
		); err != nil {
			return nil, err
		}
	}

	observations := make(
		[]domain.Observation,
		len(stored),
	)

	for i := range stored {
		observations[len(stored)-1-i] =
			stored[i].observation
	}

	return observations, nil
}

func (s *Store) loadPorts(
	ctx context.Context,
	observationID int64,
	observation *domain.Observation,
) error {
	rows, err := s.pool.Query(
		ctx,
		`
		SELECT
			port,
			protocol,
			state
		FROM port_observations
		WHERE observation_id = $1
		ORDER BY
			port,
			protocol
		`,
		observationID,
	)
	if err != nil {
		return fmt.Errorf(
			"query ports for observation %d: %w",
			observationID,
			err,
		)
	}
	defer rows.Close()

	for rows.Next() {
		var port domain.PortObservation

		if err := rows.Scan(
			&port.Port,
			&port.Protocol,
			&port.State,
		); err != nil {
			return fmt.Errorf(
				"scan port for observation %d: %w",
				observationID,
				err,
			)
		}

		observation.Ports = append(
			observation.Ports,
			port,
		)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf(
			"iterate ports for observation %d: %w",
			observationID,
			err,
		)
	}

	return nil
}

func (s *Store) loadServices(
	ctx context.Context,
	observationID int64,
	observation *domain.Observation,
) error {
	rows, err := s.pool.Query(
		ctx,
		`
		SELECT
			port,
			protocol,
			name,
			state,
			banner,
			metadata
		FROM services
		WHERE observation_id = $1
		ORDER BY
			port,
			protocol,
			name
		`,
		observationID,
	)
	if err != nil {
		return fmt.Errorf(
			"query services for observation %d: %w",
			observationID,
			err,
		)
	}
	defer rows.Close()

	for rows.Next() {
		var service domain.Service
		var state string
		var metadataJSON []byte

		if err := rows.Scan(
			&service.Port,
			&service.Protocol,
			&service.Name,
			&state,
			&service.Banner,
			&metadataJSON,
		); err != nil {
			return fmt.Errorf(
				"scan service for observation %d: %w",
				observationID,
				err,
			)
		}

		service.State = domain.ServiceState(state)

		service.Metadata = make(
			map[string]string,
		)

		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(
				metadataJSON,
				&service.Metadata,
			); err != nil {
				return fmt.Errorf(
					"decode service metadata for observation %d: %w",
					observationID,
					err,
				)
			}
		}

		observation.Services = append(
			observation.Services,
			service,
		)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf(
			"iterate services for observation %d: %w",
			observationID,
			err,
		)
	}

	return nil
}

func timeDuration(value int64) time.Duration {
	return time.Duration(value)
}
