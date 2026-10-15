package scenario

import (
	"strings"
	"testing"
	"time"

	"github.com/jbemmel/sitg/internal/config"
	"github.com/jbemmel/sitg/scenarios"
)

func TestArtificialTangoScenario(t *testing.T) {
	steps, err := Parse(strings.NewReader(scenarios.ArtificialTango), scenarios.ArtificialTangoArgs([]string{"--iface", "eth1", "--encap", "udp4", "--dst", "192.0.2.2"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 10 {
		t.Fatalf("got %d steps", len(steps))
	}
	for i, want := range map[int]config.Proto{1: config.ProtoMRC, 3: config.ProtoUET, 5: config.ProtoFalcon} {
		if steps[i].Config.Proto != want {
			t.Errorf("step %d: want %s", i+1, want)
		}
	}
	var duration time.Duration
	for _, step := range steps {
		if step.Config.RatePps != 2 {
			t.Errorf("line %d: expected 2 pps, got %d", step.Line, step.Config.RatePps)
		}
		duration += step.Config.Duration
	}
	if duration != 183*time.Second {
		t.Fatalf("duration=%s", duration)
	}
}

func TestArtificialTangoCLIOverrides(t *testing.T) {
	args := scenarios.ArtificialTangoArgs([]string{"--iface", "eth1", "--encap", "udp4", "--dst", "192.0.2.2", "--rate", "3pps", "--pkt-size", "900"})
	steps, err := Parse(strings.NewReader(scenarios.ArtificialTango), args)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range steps {
		if step.Config.RatePps != 3 || step.Config.PktSize != 900 {
			t.Fatalf("line %d lost CLI values", step.Line)
		}
	}
}
