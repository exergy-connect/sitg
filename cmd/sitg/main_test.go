package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScenarioArgs(t *testing.T) {
	for _, args := range [][]string{{"--scenario", "steps.txt", "--iface", "lo"}, {"--iface", "lo", "--scenario=steps.txt"}} {
		file, common, err := scenarioArgs(args)
		if err != nil || file != "steps.txt" || strings.Join(common, " ") != "--iface lo" {
			t.Fatalf("%q %q %v", file, common, err)
		}
	}
	for _, args := range [][]string{{"--scenario"}, {"--scenario="}, {"--scenario", "a", "--scenario", "b"}} {
		if _, _, err := scenarioArgs(args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
}

func TestScenarioValidatesBeforeOpeningInterface(t *testing.T) {
	file := filepath.Join(t.TempDir(), "steps.txt")
	if err := os.WriteFile(file, []byte("--duration 1s\n--unknown-flag\n"), 0600); err != nil {
		t.Fatal(err)
	}
	err := run(context.Background(), []string{"--scenario", file, "--iface", "nonexistent", "--role", "recv"})
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("want line 2 validation error, got %v", err)
	}
}

func TestCancelledScenarioDoesNotStart(t *testing.T) {
	file := filepath.Join(t.TempDir(), "steps.txt")
	if err := os.WriteFile(file, []byte("--duration 1s\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, []string{"--scenario", file, "--iface", "nonexistent", "--role", "recv"}); err != context.Canceled {
		t.Fatalf("got %v", err)
	}
}

// Tests run from cmd/sitg, without a scenario file in the working directory.
func TestBuiltinScenario(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := run(ctx, []string{"--scenario", "artificial-tango", "--iface", "eth1", "--encap", "udp4", "--dst", "192.0.2.2"})
	if err != context.Canceled {
		t.Fatalf("built-in scenario failed to load: %v", err)
	}
}

func TestBuiltinScenarioValidatesCommonFlags(t *testing.T) {
	err := run(context.Background(), []string{"--scenario=artificial-tango", "--iface", "eth1", "--encap", "udp4"})
	if err == nil || !strings.Contains(err.Error(), "--dst required") {
		t.Fatalf("got %v", err)
	}
}
