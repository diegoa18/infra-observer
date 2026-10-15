package postgres

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"infra-observer/internal/domain"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupTestDB(t *testing.T) (*Store, func()) {
	ctx := context.Background()

	pgContainer, err := postgres.Run(
		ctx,
		"postgres:15-alpine",
		postgres.WithInitScripts(filepath.Join("..", "..", "..", "migrations", "001_initial.sql")),
		postgres.WithDatabase("infra_observer_test"),
		postgres.WithUsername("test_user"),
		postgres.WithPassword("test_pass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(15*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %v", err)
	}

	var store *Store
	var openErr error

	// Retry loop: Absorbe los micro-cortes durante el reinicio post-migración de PostgreSQL
	for i := 0; i < 10; i++ {
		store, openErr = Open(ctx, connStr)
		if openErr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if openErr != nil {
		t.Fatalf("failed to open store after retries: %v", openErr)
	}

	cleanup := func() {
		store.Close()
		if err := testcontainers.TerminateContainer(pgContainer); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	}

	return store, cleanup
}

func TestAssetLifecycle(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	ip := "192.168.1.100"

	t1 := time.Now().UTC().Truncate(time.Millisecond)

	obs1 := domain.Observation{
		ObservedAt: t1,
		Asset:      domain.Asset{IP: ip},
		Discovery:  domain.DiscoveryEvidence{Method: "icmp"},
	}

	if err := store.SaveObservation(ctx, obs1); err != nil {
		t.Fatalf("failed to save first observation: %v", err)
	}

	t2 := t1.Add(time.Minute)
	obs2 := domain.Observation{
		ObservedAt: t2,
		Asset:      domain.Asset{IP: ip, Hostname: "web-server.local"},
		Discovery:  domain.DiscoveryEvidence{Method: "tcp"},
	}

	if err := store.SaveObservation(ctx, obs2); err != nil {
		t.Fatalf("failed to save second observation: %v", err)
	}

	inventory, err := store.Inventory(ctx, []string{ip})
	if err != nil {
		t.Fatalf("failed to get inventory: %v", err)
	}

	if len(inventory) != 1 {
		t.Fatalf("expected 1 asset in inventory, got %d", len(inventory))
	}

	asset := inventory[0]
	if asset.Asset.Hostname != "web-server.local" {
		t.Errorf("expected hostname updated to web-server.local, got %q", asset.Asset.Hostname)
	}
	if !asset.FirstSeen.Equal(t1) {
		t.Errorf("expected first_seen %v, got %v", t1, asset.FirstSeen)
	}
	if !asset.LastSeen.Equal(t2) {
		t.Errorf("expected last_seen %v, got %v", t2, asset.LastSeen)
	}
}

func TestInventoryConsolidation(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	ip := "10.0.0.50"

	t1 := time.Now().UTC().Truncate(time.Millisecond)
	obs1 := domain.Observation{
		ObservedAt: t1,
		Asset:      domain.Asset{IP: ip},
		Discovery:  domain.DiscoveryEvidence{Method: "icmp"},
		Ports: []domain.PortObservation{
			{Port: 22, Protocol: "tcp", State: "open"},
			{Port: 80, Protocol: "tcp", State: "closed"},
		},
	}
	if err := store.SaveObservation(ctx, obs1); err != nil {
		t.Fatalf("failed to save obs1: %v", err)
	}

	t2 := t1.Add(time.Hour)
	obs2 := domain.Observation{
		ObservedAt: t2,
		Asset:      domain.Asset{IP: ip},
		Discovery:  domain.DiscoveryEvidence{Method: "tcp"},
		Ports: []domain.PortObservation{
			{Port: 8080, Protocol: "tcp", State: "open"},
		},
		Services: []domain.Service{
			{
				Port:     8080,
				Protocol: "tcp",
				Name:     "HTTP",
				State:    domain.ServiceAccessible,
			},
		},
	}
	if err := store.SaveObservation(ctx, obs2); err != nil {
		t.Fatalf("failed to save obs2: %v", err)
	}

	inventory, err := store.Inventory(ctx, []string{ip})
	if err != nil {
		t.Fatalf("failed to get inventory: %v", err)
	}

	if len(inventory) != 1 {
		t.Fatalf("expected 1 asset in inventory, got %d", len(inventory))
	}

	ports := inventory[0].Ports
	if len(ports) != 3 {
		t.Fatalf("expected 3 consolidated ports, got %d", len(ports))
	}

	for _, p := range ports {
		switch p.Port {
		case 22:
			if p.State != "open" || !p.LastObservedAt.Equal(t1) {
				t.Errorf("port 22 state/time invalid")
			}
		case 80:
			if p.State != "closed" || !p.LastObservedAt.Equal(t1) {
				t.Errorf("port 80 state/time invalid")
			}
		case 8080:
			if p.State != "open" || !p.LastObservedAt.Equal(t2) {
				t.Errorf("port 8080 state/time invalid")
			}
			if p.Service == nil || p.Service.Name != "HTTP" {
				t.Errorf("expected HTTP service on port 8080")
			}
		default:
			t.Errorf("unexpected port %d in inventory", p.Port)
		}
	}
}

func TestLatestObservationsReconstruction(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	ip := "172.16.0.1"

	t1 := time.Now().UTC().Truncate(time.Millisecond)
	obs1 := domain.Observation{
		ObservedAt: t1,
		Asset:      domain.Asset{IP: ip},
		Discovery:  domain.DiscoveryEvidence{Method: "icmp", Reason: "echo-reply", RTT: 5 * time.Millisecond},
		Ports: []domain.PortObservation{
			{Port: 443, Protocol: "tcp", State: "open"},
		},
		Services: []domain.Service{
			{Port: 443, Protocol: "tcp", Name: "HTTPS", State: domain.ServiceAccessible},
		},
	}
	_ = store.SaveObservation(ctx, obs1)

	t2 := t1.Add(time.Minute)
	obs2 := domain.Observation{
		ObservedAt: t2,
		Asset:      domain.Asset{IP: ip},
		Discovery:  domain.DiscoveryEvidence{Method: "tcp", Reason: "conn-refused"},
		Ports: []domain.PortObservation{
			{Port: 443, Protocol: "tcp", State: "closed"},
		},
	}
	_ = store.SaveObservation(ctx, obs2)

	limit := 2
	observations, err := store.LatestObservations(ctx, ip, limit)
	if err != nil {
		t.Fatalf("failed to get latest observations: %v", err)
	}

	if len(observations) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(observations))
	}

	if !observations[0].ObservedAt.Equal(t1) {
		t.Errorf("expected observation 0 to be t1")
	}
	if len(observations[0].Services) != 1 || observations[0].Services[0].Name != "HTTPS" {
		t.Errorf("expected observation 0 to have HTTPS service")
	}

	if !observations[1].ObservedAt.Equal(t2) {
		t.Errorf("expected observation 1 to be t2")
	}
	if observations[1].Ports[0].State != "closed" {
		t.Errorf("expected observation 1 to show port 443 closed")
	}
}
