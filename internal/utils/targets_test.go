package utils

import (
	"reflect"
	"testing"
)

func TestParseTargetIPv4(t *testing.T) {
	got, err := ParseTarget("192.168.1.10")
	if err != nil {
		t.Fatalf("ParseTarget() error = %v", err)
	}

	want := []string{"192.168.1.10"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"ParseTarget() = %v, want %v",
			got,
			want,
		)
	}
}

func TestParseTargetCIDR(t *testing.T) {
	got, err := ParseTarget("192.168.1.0/30")
	if err != nil {
		t.Fatalf("ParseTarget() error = %v", err)
	}

	want := []string{
		"192.168.1.0",
		"192.168.1.1",
		"192.168.1.2",
		"192.168.1.3",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"ParseTarget() = %v, want %v",
			got,
			want,
		)
	}
}

func TestParseTargetRejectsIPv6(t *testing.T) {
	if _, err := ParseTarget("::1"); err == nil {
		t.Fatal("expected IPv6 target to be rejected")
	}
}

func TestParseTargetRejectsOversizedNetwork(t *testing.T) {
	if _, err := ParseTarget("10.0.0.0/16"); err == nil {
		t.Fatal("expected oversized network to be rejected")
	}
}
