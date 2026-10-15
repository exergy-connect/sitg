package config

import "testing"

func TestPacketRates(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want uint64
	}{
		{"1000pps", 1000}, {"1.5Kpps", 1500}, {"2Mpps", 2000000}, {"1Gpps", 1000000000}, {" 5PPS ", 5},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			cfg, err := Parse([]string{"--iface", "lo", "--role", "recv", "--rate", tc.raw})
			if err != nil {
				t.Fatal(err)
			}
			if cfg.RatePps != tc.want || cfg.RateBps != 0 {
				t.Fatalf("got pps=%d bps=%d", cfg.RatePps, cfg.RateBps)
			}
		})
	}
	for _, raw := range []string{"0pps", "-1pps", "NaNpps", "Infpps", "1e100pps", "oopspps"} {
		if _, err := Parse([]string{"--iface", "lo", "--role", "recv", "--rate", raw}); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}
