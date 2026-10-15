package config

import (
	"testing"
	"time"
)

func TestDurationIntegerSeconds(t *testing.T) {
	for _, raw := range []string{"0", "0s", "10", "10s"} {
		cfg, err := Parse([]string{"--iface", "lo", "--role", "recv", "--duration", raw})
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		want := 10 * time.Second
		if raw == "0" || raw == "0s" {
			want = 0
		}
		if cfg.Duration != want {
			t.Fatalf("%s: got %s", raw, cfg.Duration)
		}
	}
	for _, raw := range []string{"", "1.5s", "1.0s", "500ms", "1000ms", "1m", "-1s", "-1", "+1", "NaN", "9223372037s", "18446744073709551616"} {
		if _, err := Parse([]string{"--iface", "lo", "--role", "recv", "--duration", raw}); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}
