package models

import (
	"testing"
	"time"
)

func TestParseTTL(t *testing.T) {
	tests := []struct {
		value    string
		fallback time.Duration
		want     time.Duration
	}{
		{"", time.Hour, time.Hour},                     // empty uses fallback
		{"30m", time.Hour, 30 * time.Minute},           // valid override
		{"2h", time.Hour, 2 * time.Hour},               // valid override
		{"720h", time.Hour, 720 * time.Hour},            // valid override
		{"not-a-duration", time.Hour, time.Hour},        // invalid uses fallback
	}
	for _, tt := range tests {
		got := ParseTTL(tt.value, tt.fallback)
		if got != tt.want {
			t.Errorf("ParseTTL(%q, %v) = %v, want %v", tt.value, tt.fallback, got, tt.want)
		}
	}
}
