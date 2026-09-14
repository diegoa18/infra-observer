package change

import (
	"testing"
	"time"

	"infra-observer/internal/domain"
)

func TestCompareDetectsPortStateChange(t *testing.T) {
	previous := domain.Observation{
		ObservedAt: time.Now(),
		Ports: []domain.PortObservation{
			{
				Port:     8080,
				Protocol: "tcp",
				State:    "closed",
			},
		},
	}

	current := domain.Observation{
		ObservedAt: time.Now(),
		Ports: []domain.PortObservation{
			{
				Port:     8080,
				Protocol: "tcp",
				State:    "open",
			},
		},
	}

	result := Compare(previous, current)

	if len(result.Ports) != 1 {
		t.Fatalf(
			"got %d port changes, want 1",
			len(result.Ports),
		)
	}

	got := result.Ports[0]

	if got.Port != 8080 {
		t.Fatalf(
			"port = %d, want 8080",
			got.Port,
		)
	}

	if got.Before != "closed" {
		t.Fatalf(
			"before = %q, want %q",
			got.Before,
			"closed",
		)
	}

	if got.After != "open" {
		t.Fatalf(
			"after = %q, want %q",
			got.After,
			"open",
		)
	}
}

func TestCompareIgnoresUnobservedPorts(t *testing.T) {
	previous := domain.Observation{
		Ports: []domain.PortObservation{
			{
				Port:     22,
				Protocol: "tcp",
				State:    "open",
			},
			{
				Port:     8080,
				Protocol: "tcp",
				State:    "closed",
			},
		},
	}

	current := domain.Observation{
		Ports: []domain.PortObservation{
			{
				Port:     8080,
				Protocol: "tcp",
				State:    "closed",
			},
		},
	}

	result := Compare(previous, current)

	if !result.Empty() {
		t.Fatalf(
			"expected no changes, got %+v",
			result,
		)
	}
}

func TestCompareDetectsServiceAdded(t *testing.T) {
	previous := domain.Observation{
		Ports: []domain.PortObservation{
			{
				Port:     8080,
				Protocol: "tcp",
				State:    "closed",
			},
		},
	}

	current := domain.Observation{
		Ports: []domain.PortObservation{
			{
				Port:     8080,
				Protocol: "tcp",
				State:    "open",
			},
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

	result := Compare(previous, current)

	if len(result.Services) != 1 {
		t.Fatalf(
			"got %d service changes, want 1",
			len(result.Services),
		)
	}

	got := result.Services[0]

	if got.Kind != ServiceAdded {
		t.Fatalf(
			"kind = %q, want %q",
			got.Kind,
			ServiceAdded,
		)
	}

	if got.AfterName != "HTTP" {
		t.Fatalf(
			"service = %q, want %q",
			got.AfterName,
			"HTTP",
		)
	}
}

func TestCompareDetectsServiceRemoved(t *testing.T) {
	previous := domain.Observation{
		Ports: []domain.PortObservation{
			{
				Port:     8080,
				Protocol: "tcp",
				State:    "open",
			},
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

	current := domain.Observation{
		Ports: []domain.PortObservation{
			{
				Port:     8080,
				Protocol: "tcp",
				State:    "closed",
			},
		},
	}

	result := Compare(previous, current)

	if len(result.Services) != 1 {
		t.Fatalf(
			"got %d service changes, want 1",
			len(result.Services),
		)
	}

	if result.Services[0].Kind != ServiceRemoved {
		t.Fatalf(
			"kind = %q, want %q",
			result.Services[0].Kind,
			ServiceRemoved,
		)
	}
}
