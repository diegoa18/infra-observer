package utils

import (
	"reflect"
	"testing"
)

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []int
	}{
		{
			name:  "single port",
			input: "80",
			want:  []int{80},
		},
		{
			name:  "multiple ports",
			input: "22,80,443",
			want:  []int{22, 80, 443},
		},
		{
			name:  "range",
			input: "80-82",
			want:  []int{80, 81, 82},
		},
		{
			name:  "mixed values",
			input: "443,22,80-82",
			want:  []int{22, 80, 81, 82, 443},
		},
		{
			name:  "duplicates",
			input: "80,80,81-82,82",
			want:  []int{80, 81, 82},
		},
		{
			name:  "spaces",
			input: "22, 80, 443",
			want:  []int{22, 80, 443},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortRange(tt.input)
			if err != nil {
				t.Fatalf(
					"ParsePortRange() error = %v",
					err,
				)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf(
					"ParsePortRange() = %v, want %v",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestParsePortRangeRejectsInvalidValues(t *testing.T) {
	tests := []string{
		"",
		"0",
		"65536",
		"80-",
		"-80",
		"100-50",
		"abc",
		"80,,443",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := ParsePortRange(input); err == nil {
				t.Fatalf(
					"expected error for %q",
					input,
				)
			}
		})
	}
}
