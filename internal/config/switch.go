package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SwitchLimit counts original payload traffic; ACKs and retries do not count.
type SwitchLimit struct {
	Interval time.Duration
	Packets  uint64
	Bytes    uint64
}

func parseSwitchLimit(raw string) (SwitchLimit, error) {
	s := strings.TrimSpace(raw)
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return SwitchLimit{Interval: d}, nil
	}
	for _, suffix := range []string{"packets", "packet", "pkts", "pkt"} {
		if strings.HasSuffix(s, suffix) {
			n, err := strconv.ParseUint(strings.TrimSpace(strings.TrimSuffix(s, suffix)), 10, 64)
			if err == nil && n > 0 {
				return SwitchLimit{Packets: n}, nil
			}
			return SwitchLimit{}, fmt.Errorf("invalid packet count %q", raw)
		}
	}
	for _, unit := range []struct {
		suffix     string
		multiplier uint64
		bits       bool
	}{
		{"GiB", 1 << 30, false}, {"MiB", 1 << 20, false}, {"KiB", 1 << 10, false},
		{"Gib", 1 << 30, true}, {"Mib", 1 << 20, true}, {"Kib", 1 << 10, true},
		{"GB", 1_000_000_000, false}, {"MB", 1_000_000, false}, {"KB", 1_000, false},
		{"Gb", 1_000_000_000, true}, {"Mb", 1_000_000, true}, {"Kb", 1_000, true},
		{"B", 1, false}, {"b", 1, true},
	} {
		if !strings.HasSuffix(s, unit.suffix) {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(strings.TrimSuffix(s, unit.suffix)), 10, 64)
		if err != nil || n == 0 || n > ^uint64(0)/unit.multiplier {
			break
		}
		n *= unit.multiplier
		if unit.bits {
			n = n/8 + boolUint(n%8 != 0)
		}
		return SwitchLimit{Bytes: n}, nil
	}
	return SwitchLimit{}, fmt.Errorf("invalid threshold %q (use 1s, 100packets, 1Mb, or 1MB)", raw)
}

func boolUint(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}
