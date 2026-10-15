package engine

import (
	"github.com/jbemmel/sitg/internal/config"
	"testing"
)

func TestPacketRateCosts(t *testing.T) {
	e := &Engine{cfg: &config.Config{RatePps: 10}}
	if e.rateTokens() != 10 || e.packetCost(64) != 1 || e.packetCost(9000) != 1 {
		t.Fatal("packet rates must be independent of size")
	}
	e.cfg.RatePps = 0
	e.cfg.RateBps = 1000
	if e.rateTokens() != 1000 || e.packetCost(64) != 512 {
		t.Fatal("bit rate accounting changed")
	}
}
