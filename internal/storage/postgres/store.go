package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"infra-observer/internal/domain"
	"infra-observer/migrations"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ domain.Repository = (*Store)(nil)

type Store struct {
	pool *pgxpool.Pool
}

type storedObservation struct {
	id          int64
	observation domain.Observation
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

	store := &Store{
		pool: pool,
	}

	if err := store.ensureMigrations(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) ensureMigrations(ctx context.Context) error {
	var exists bool
	if err := s.pool.QueryRow(ctx, checkAssetsTableExistsSQL).Scan(&exists); err != nil {
		return fmt.Errorf("check schema migration status: %w", err)
	}

	if exists {
		return nil
	}

	migrationSQL, err := migrations.FS.ReadFile("001_initial.sql")
	if err != nil {
		return fmt.Errorf("read embedded migration: %w", err)
	}

	if _, err := s.pool.Exec(ctx, string(migrationSQL)); err != nil {
		return fmt.Errorf("execute embedded migration: %w", err)
	}

	return nil
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
		upsertAssetSQL,
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
		insertObservationSQL,
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

	totalBatchItems := len(observation.Ports) + len(observation.Services)
	if totalBatchItems > 0 {
		batch := &pgx.Batch{}

		for _, port := range observation.Ports {
			batch.Queue(
				insertPortObservationSQL,
				observationID,
				port.Port,
				port.Protocol,
				port.State,
			)
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

			batch.Queue(
				insertServiceSQL,
				observationID,
				service.Port,
				service.Protocol,
				service.Name,
				string(service.State),
				service.Banner,
				string(metadataJSON),
			)
		}

		br := tx.SendBatch(ctx, batch)
		for i := 0; i < totalBatchItems; i++ {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				return fmt.Errorf(
					"batch insert observation details for %s: %w",
					observation.Asset.IP,
					err,
				)
			}
		}

		if err := br.Close(); err != nil {
			return fmt.Errorf(
				"close batch for %s: %w",
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
		selectLatestObservationsSQL,
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

		item.observation.Discovery.RTT = timeDuration(discoveryRTT)
		stored = append(stored, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate observations for %s: %w",
			ip,
			err,
		)
	}

	rows.Close()

	if len(stored) == 0 {
		return nil, nil
	}

	obsIDs := make([]int64, len(stored))
	indexByObsID := make(map[int64]int, len(stored))

	for i, item := range stored {
		obsIDs[i] = item.id
		indexByObsID[item.id] = i
	}

	if err := s.loadPortsBulk(ctx, obsIDs, indexByObsID, stored); err != nil {
		return nil, err
	}

	if err := s.loadServicesBulk(ctx, obsIDs, indexByObsID, stored); err != nil {
		return nil, err
	}

	observations := make(
		[]domain.Observation,
		len(stored),
	)

	for i := range stored {
		observations[len(stored)-1-i] = stored[i].observation
	}

	return observations, nil
}

func (s *Store) loadPortsBulk(
	ctx context.Context,
	obsIDs []int64,
	indexByObsID map[int64]int,
	stored []storedObservation,
) error {
	rows, err := s.pool.Query(
		ctx,
		selectPortsByObservationsSQL,
		obsIDs,
	)
	if err != nil {
		return fmt.Errorf("query bulk ports: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var obsID int64
		var port domain.PortObservation

		if err := rows.Scan(
			&obsID,
			&port.Port,
			&port.Protocol,
			&port.State,
		); err != nil {
			return fmt.Errorf("scan port observation: %w", err)
		}

		if idx, exists := indexByObsID[obsID]; exists {
			stored[idx].observation.Ports = append(
				stored[idx].observation.Ports,
				port,
			)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate bulk ports: %w", err)
	}

	return nil
}

func (s *Store) loadServicesBulk(
	ctx context.Context,
	obsIDs []int64,
	indexByObsID map[int64]int,
	stored []storedObservation,
) error {
	rows, err := s.pool.Query(
		ctx,
		selectServicesByObservationsSQL,
		obsIDs,
	)
	if err != nil {
		return fmt.Errorf("query bulk services: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var obsID int64
		var service domain.Service
		var state string
		var metadataJSON []byte

		if err := rows.Scan(
			&obsID,
			&service.Port,
			&service.Protocol,
			&service.Name,
			&state,
			&service.Banner,
			&metadataJSON,
		); err != nil {
			return fmt.Errorf("scan service observation: %w", err)
		}

		service.State = domain.ServiceState(state)
		service.Metadata = make(map[string]string)

		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(
				metadataJSON,
				&service.Metadata,
			); err != nil {
				return fmt.Errorf(
					"decode service metadata for observation %d: %w",
					obsID,
					err,
				)
			}
		}

		if idx, exists := indexByObsID[obsID]; exists {
			stored[idx].observation.Services = append(
				stored[idx].observation.Services,
				service,
			)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate bulk services: %w", err)
	}

	return nil
}

func timeDuration(value int64) time.Duration {
	return time.Duration(value)
}
