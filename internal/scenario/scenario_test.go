package scenario

import (
	"strings"
	"testing"
)

func TestParseSteps(t *testing.T) {
	text := `# traffic sequence

--proto uet --rate '10pps' # slow
  # indented comment
sitg --proto falcon --rate="2Kpps" --duration 2s
--proto mixed --switch-every 10packets
`
	steps, err := Parse(strings.NewReader(text), []string{"--iface", "lo", "--dst", "127.0.0.1", "--encap", "udp4", "--rate", "1Mbps"})
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 3 {
		t.Fatalf("steps=%d", len(steps))
	}
	if steps[0].Line != 3 || steps[1].Line != 5 || steps[2].Line != 6 {
		t.Fatal("incorrect line numbers")
	}
	if steps[0].Config.RatePps != 10 || steps[1].Config.RatePps != 2000 || steps[2].Config.RatePps != 2000 || steps[2].Config.RateBps != 0 {
		t.Fatal("incorrect rate overrides")
	}
	if steps[1].Config.Duration.Seconds() != 2 || steps[2].Config.SwitchEvery.Packets != 10 || steps[2].Config.Duration.Seconds() != 2 {
		t.Fatal("incorrect step parameters")
	}
}

func TestInvalidScenario(t *testing.T) {
	for _, text := range []string{"", "# comment", "--rate '10pps", "--iface lo\\", "--no-such-flag x", "echo hello", "sitg", "--rate 0pps", "--duration 1s\n--bad-flag"} {
		t.Run(text, func(t *testing.T) {
			steps, err := Parse(strings.NewReader(text), []string{"--iface", "lo", "--role", "recv"})
			if err == nil || steps != nil {
				t.Fatalf("accepted invalid script: %q", text)
			}
			if strings.TrimSpace(text) != "" && text != "# comment" && !strings.Contains(err.Error(), "line ") {
				t.Fatalf("missing line: %v", err)
			}
		})
	}
}

func TestSplit(t *testing.T) {
	got, err := split(`--iface eth\ 1 --dst "192.0.2.1" --value '' --literal 'x#y' # end`)
	want := []string{"--iface", "eth 1", "--dst", "192.0.2.1", "--value", "", "--literal", "x#y"}
	if err != nil || strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("%q %v", got, err)
	}
}

func TestDifferentialParameters(t *testing.T) {
	common := []string{"--iface", "eth1", "--dst", "192.0.2.1", "--encap", "udp4", "--rate", "2pps", "--dst-mac", "02:00:00:00:00:01", "--qp", "7"}
	text := "--proto mrc --duration 8s\n--proto uet --iface eth2 --dst 192.0.2.2 --rate 3pps\n# keep all parameters\n--duration=4s --dst-mac=''\n--proto falcon\n"
	steps, err := Parse(strings.NewReader(text), common)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 4 {
		t.Fatalf("steps=%d", len(steps))
	}
	for i, step := range steps {
		cfg := step.Config
		if cfg.QP != 7 || cfg.Encap != "udp4" {
			t.Fatalf("step %d lost CLI parameters", i)
		}
		if i > 0 && (cfg.Iface != "eth2" || cfg.Dst.String() != "192.0.2.2" || cfg.RatePps != 3) {
			t.Fatalf("step %d lost prior overrides", i)
		}
	}
	if steps[0].Config.Iface != "eth1" || steps[0].Config.RatePps != 2 || steps[0].Config.Dst.String() != "192.0.2.1" {
		t.Fatal("later steps mutated earlier config")
	}
	if steps[1].Config.Duration.Seconds() != 8 || steps[1].Config.DstMAC == nil {
		t.Fatal("omitted parameters did not carry forward")
	}
	for _, step := range steps[2:] {
		if step.Config.Duration.Seconds() != 4 || step.Config.DstMAC != nil {
			t.Fatal("explicit clearing or duration failed to persist")
		}
	}
}
