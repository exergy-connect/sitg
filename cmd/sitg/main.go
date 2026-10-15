package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jbemmel/sitg/internal/config"
	"github.com/jbemmel/sitg/internal/engine"
	"github.com/jbemmel/sitg/internal/link"
	"github.com/jbemmel/sitg/internal/scenario"
	"github.com/jbemmel/sitg/scenarios"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "  --scenario NAME|FILE\n        play built-in artificial-tango or a file (- reads stdin); other flags supply shared defaults")
			return
		}
		fmt.Fprintf(os.Stderr, "sitg: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	file, common, err := scenarioArgs(args)
	if err != nil {
		return err
	}
	if file == "" {
		cfg, err := config.Parse(common)
		if err != nil {
			return err
		}
		cfg.ApplyPatternDefaults()
		return runSession(ctx, cfg)
	}
	var steps []scenario.Step
	if file == "artificial-tango" {
		steps, err = scenario.Parse(strings.NewReader(scenarios.ArtificialTango), common)
	} else if file == "-" {
		steps, err = scenario.Parse(os.Stdin, common)
	} else {
		f, openErr := os.Open(file)
		if openErr != nil {
			return openErr
		}
		steps, err = scenario.Parse(f, common)
		f.Close()
	}
	if err != nil {
		return fmt.Errorf("scenario %s: %w", file, err)
	}
	for i, step := range steps {
		if err := ctx.Err(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "sitg scenario %s: step %d/%d (line %d)\n", file, i+1, len(steps), step.Line)
		if err := runSession(ctx, step.Config); err != nil {
			return fmt.Errorf("scenario %s line %d: %w", file, step.Line, err)
		}
	}
	return ctx.Err()
}

func scenarioArgs(args []string) (string, []string, error) {
	var file string
	var common []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--scenario" || arg == "-scenario" || strings.HasPrefix(arg, "--scenario=") || strings.HasPrefix(arg, "-scenario=") {
			if file != "" {
				return "", nil, fmt.Errorf("--scenario may only be specified once")
			}
			if _, value, ok := strings.Cut(arg, "="); ok {
				file = value
			} else {
				i++
				if i >= len(args) {
					return "", nil, fmt.Errorf("--scenario requires a built-in name, file path, or - for stdin")
				}
				file = args[i]
			}
			if file == "" {
				return "", nil, fmt.Errorf("--scenario requires a nonempty name or file path")
			}
		} else {
			common = append(common, arg)
		}
	}
	return file, common, nil
}

func runSession(ctx context.Context, cfg *config.Config) error {
	ep, err := link.ResolveEndpoint(cfg.Iface)
	if err != nil {
		return err
	}
	sock, err := link.OpenSocket(ep, cfg.IPProto)
	if err != nil {
		return err
	}
	defer sock.Close()
	eng, err := engine.New(cfg, sock)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "sitg %s proto=%s encap=%s iface=%s entropy=%s\n", cfg.Role, cfg.Proto, cfg.Encap, cfg.Iface, cfg.Entropy)
	return eng.RunContext(ctx)
}
