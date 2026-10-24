package postgres

const (
	checkAssetsTableExistsSQL = `
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_schema = 'public'
			AND table_name = 'assets'
		)
	`

	upsertAssetSQL = `
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
	`

	insertObservationSQL = `
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
	`

	insertPortObservationSQL = `
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
	`

	insertServiceSQL = `
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
	`

	selectLatestObservationsSQL = `
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
	`

	selectPortsByObservationsSQL = `
		SELECT
			observation_id,
			port,
			protocol,
			state
		FROM port_observations
		WHERE observation_id = ANY($1::bigint[])
		ORDER BY
			observation_id,
			port,
			protocol
	`

	selectServicesByObservationsSQL = `
		SELECT
			observation_id,
			port,
			protocol,
			name,
			state,
			banner,
			metadata
		FROM services
		WHERE observation_id = ANY($1::bigint[])
		ORDER BY
			observation_id,
			port,
			protocol,
			name
	`

	selectAllInventoryAssetsSQL = `
		SELECT
			id,
			host(ip),
			COALESCE(hostname, ''),
			first_seen,
			last_seen
		FROM assets
		ORDER BY ip
	`

	selectFilteredInventoryAssetsSQL = `
		SELECT
			id,
			host(ip),
			COALESCE(hostname, ''),
			first_seen,
			last_seen
		FROM assets
		WHERE host(ip) = ANY($1::text[])
		ORDER BY ip
	`

	selectInventoryPortsByAssetsSQL = `
		SELECT DISTINCT ON (
			o.asset_id,
			po.protocol,
			po.port
		)
			o.asset_id,
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
		WHERE o.asset_id = ANY($1::bigint[])
		ORDER BY
			o.asset_id,
			po.protocol,
			po.port,
			o.observed_at DESC,
			o.id DESC
	`
)
