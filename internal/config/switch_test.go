package config

import (
	"testing"
	"time"
)

func TestSwitchLimit(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want SwitchLimit
	}{
		{"1s", SwitchLimit{Interval: time.Second}},
		{"250ms", SwitchLimit{Interval: 250 * time.Millisecond}},
		{"100packets", SwitchLimit{Packets: 100}},
		{"100 pkts", SwitchLimit{Packets: 100}},
		{"1Mb", SwitchLimit{Bytes: 125000}},
		{"1MB", SwitchLimit{Bytes: 1000000}},
		{"1MiB", SwitchLimit{Bytes: 1048576}},
		{"9b", SwitchLimit{Bytes: 2}},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := parseSwitchLimit(tc.raw)
			if err != nil || got != tc.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
	for _, raw := range []string{"", "0s", "-1s", "0packets", "0B", "100", "1Mbps", "18446744073709551615MB"} {
		if _, err := parseSwitchLimit(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestMixedValidation(t *testing.T) {
	base := []string{"--iface", "lo", "--proto", "mixed", "--dst", "::1"}
	for _, extra := range [][]string{{"--role", "recv"}, {"--encap", "ip6"}, {"--qp", "16777216"}, {"--switch-every", "0s"}} {
		if _, err := Parse(append(append([]string(nil), base...), extra...)); err == nil {
			t.Fatalf("accepted %v", extra)
		}
	}
}
