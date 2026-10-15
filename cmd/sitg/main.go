package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"math/big"
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
		steps, err = scenario.Parse(strings.NewReader(scenarios.ArtificialTango), scenarios.ArtificialTangoArgs(common))
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
	// A new QP per Tango section isolates receiver sequence state across runs.
	if file == "artificial-tango" {
		base, err := rand.Int(rand.Reader, big.NewInt(int64(65535-len(steps))))
		if err != nil {
			return fmt.Errorf("allocate scenario QPs: %w", err)
		}
		for i := range steps {
			steps[i].Config.QP = uint32(base.Int64()) + 1 + uint32(i)
		}
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
	if err := ctx.Err(); err != nil {
		return err
	}
	// Prepare every interface before starting traffic. Each receiver owns its
	// sockets, sequence tracking and replies, including Falcon CM listeners.
	var sessions []func(context.Context) error
	for _, name := range strings.Split(cfg.Iface, ",") {
		local := *cfg
		local.Iface = name
		ep, err := link.ResolveEndpoint(name)
		if err != nil {
			return fmt.Errorf("interface %s: %w", name, err)
		}
		sock, err := link.OpenSocket(ep, cfg.IPProto)
		if err != nil {
			return fmt.Errorf("interface %s: %w", name, err)
		}
		defer sock.Close()
		eng, err := engine.New(&local, sock)
		if err != nil {
			return fmt.Errorf("interface %s: %w", name, err)
		}
		sessions = append(sessions, func(ctx context.Context) error {
			if err := eng.RunContext(ctx); err != nil {
				return fmt.Errorf("interface %s: %w", name, err)
			}
			return nil
		})
	}
	fmt.Fprintf(os.Stderr, "sitg %s proto=%s encap=%s iface=%s entropy=%s qp=%d\n", cfg.Role, cfg.Proto, cfg.Encap, cfg.Iface, cfg.Entropy, cfg.QP)
	return runSessions(ctx, sessions)
}

// A failed receiver stops its siblings; always join them before closing sockets.
func runSessions(ctx context.Context, sessions []func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(sessions))
	for _, session := range sessions {
		go func() { results <- session(ctx) }()
	}
	var first error
	for range sessions {
		if err := <-results; err != nil && first == nil {
			first = err
			cancel()
		}
	}
	return first
}
