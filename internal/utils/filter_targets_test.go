package utils

import (
	"reflect"
	"testing"
)

func TestFilterTargetsRemovesProhibitedNetworks(t *testing.T) {
	targets := []TargetInfo{
		{IP: "169.254.169.254"},
		{IP: "224.0.0.1"},
		{IP: "239.255.255.255"},
		{IP: "255.255.255.255"},
		{IP: "192.168.1.10"},
	}

	got := FilterTargets(targets, nil)
	want := []TargetInfo{{IP: "192.168.1.10"}}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FilterTargets() = %v, want %v", got, want)
	}
}

func TestFilterTargetsHonorsExcludeIPsAndCIDRs(t *testing.T) {
	targets := []TargetInfo{
		{IP: "10.0.0.5"},
		{IP: "10.0.1.5"},
		{IP: "192.168.1.10"},
		{IP: "172.16.0.1"},
	}

	got := FilterTargets(targets, []string{"10.0.0.5", "172.16.0.0/12"})
	want := []TargetInfo{
		{IP: "10.0.1.5"},
		{IP: "192.168.1.10"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FilterTargets() = %v, want %v", got, want)
	}
}

func TestFilterTargetsIgnoresInvalidExcludes(t *testing.T) {
	targets := []TargetInfo{{IP: "192.168.1.10"}}

	got := FilterTargets(targets, []string{"", "not-an-ip", "192.168.1.0/33"})
	want := []TargetInfo{{IP: "192.168.1.10"}}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FilterTargets() = %v, want %v", got, want)
	}
}
