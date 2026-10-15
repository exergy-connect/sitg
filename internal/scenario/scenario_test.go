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
	if steps[0].Config.RatePps != 10 || steps[1].Config.RatePps != 2000 || steps[2].Config.RateBps != 1000000 {
		t.Fatal("incorrect rate overrides")
	}
	if steps[1].Config.Duration.Seconds() != 2 || steps[2].Config.SwitchEvery.Packets != 10 {
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
