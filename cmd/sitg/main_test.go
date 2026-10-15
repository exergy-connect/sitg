package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSessionsCancelAndJoinOnFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	want := errors.New("receiver failed")
	started, stopped := make(chan struct{}), make(chan struct{})
	err := runSessions(ctx, []func(context.Context) error{
		func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(stopped)
			return nil
		},
		func(context.Context) error { <-started; return want },
	})
	if !errors.Is(err, want) || ctx.Err() != nil {
		t.Fatalf("got %v, parent=%v", err, ctx.Err())
	}
	select {
	case <-stopped:
	default:
		t.Fatal("returned before sibling receiver stopped")
	}
}

func TestSessionsRunAllUntilComplete(t *testing.T) {
	ready, release := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := runSessions(ctx, []func(context.Context) error{
		func(ctx context.Context) error {
			close(ready)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		func(ctx context.Context) error {
			select {
			case <-ready:
				close(release)
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

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
