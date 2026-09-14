BEGIN;

CREATE TABLE assets (
    id BIGSERIAL PRIMARY KEY,
    ip INET NOT NULL UNIQUE,
    hostname TEXT,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,

    CONSTRAINT assets_seen_order
        CHECK (last_seen >= first_seen)
);

CREATE TABLE observations (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT NOT NULL
        REFERENCES assets(id)
        ON DELETE CASCADE,

    observed_at TIMESTAMPTZ NOT NULL,
    discovery_method TEXT NOT NULL,
    discovery_rtt_ns BIGINT NOT NULL DEFAULT 0,
    discovery_reason TEXT NOT NULL,

    CONSTRAINT observations_rtt_nonnegative
        CHECK (discovery_rtt_ns >= 0)
);

CREATE TABLE port_observations (
    id BIGSERIAL PRIMARY KEY,
    observation_id BIGINT NOT NULL
        REFERENCES observations(id)
        ON DELETE CASCADE,

    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,

    CONSTRAINT port_observations_port_range
        CHECK (port BETWEEN 1 AND 65535),

    CONSTRAINT port_observations_state
        CHECK (state IN ('open', 'closed', 'unknown')),

    CONSTRAINT port_observations_unique
        UNIQUE (observation_id, protocol, port)
);

CREATE TABLE services (
    id BIGSERIAL PRIMARY KEY,
    observation_id BIGINT NOT NULL
        REFERENCES observations(id)
        ON DELETE CASCADE,

    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    name TEXT NOT NULL,
    state TEXT NOT NULL,
    banner TEXT NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT services_port_range
        CHECK (port BETWEEN 1 AND 65535),

    CONSTRAINT services_unique
        UNIQUE (observation_id, protocol, port, name)
);

CREATE INDEX observations_asset_time_idx
    ON observations (asset_id, observed_at DESC);

CREATE INDEX port_observations_observation_idx
    ON port_observations (observation_id);

CREATE INDEX services_observation_idx
    ON services (observation_id);

COMMIT;
