package scenario

import (
	"strings"
	"testing"
	"time"

	"github.com/jbemmel/sitg/internal/config"
	"github.com/jbemmel/sitg/scenarios"
)

func TestArtificialTangoScenario(t *testing.T) {
	steps, err := Parse(strings.NewReader(scenarios.ArtificialTango), []string{"--iface", "eth1", "--encap", "udp4", "--dst", "192.0.2.2"})
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
		duration += step.Config.Duration
	}
	if duration != 182760*time.Millisecond {
		t.Fatalf("duration=%s", duration)
	}
}
