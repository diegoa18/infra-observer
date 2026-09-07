package domain

import "testing"

func TestPortStateValues(t *testing.T) {
	if PortOpen != "open" {
		t.Fatalf("PortOpen = %q", PortOpen)
	}

	if PortClosed != "closed" {
		t.Fatalf("PortClosed = %q", PortClosed)
	}

	if PortUnknown != "unknown" {
		t.Fatalf("PortUnknown = %q", PortUnknown)
	}
}
