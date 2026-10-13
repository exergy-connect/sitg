package main

import (
	"fmt"
	"os"

	"github.com/jbemmel/sitg/internal/config"
	"github.com/jbemmel/sitg/internal/engine"
	"github.com/jbemmel/sitg/internal/link"
)

func main() {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sitg: %v\n", err)
		os.Exit(2)
	}
	cfg.ApplyPatternDefaults()

	ep, err := link.ResolveEndpoint(cfg.Iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sitg: %v\n", err)
		os.Exit(1)
	}
	sock, err := link.OpenSocket(ep, cfg.IPProto)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sitg: %v\n", err)
		os.Exit(1)
	}
	defer sock.Close()

	eng, err := engine.New(cfg, sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sitg: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "sitg %s proto=%s encap=%s iface=%s entropy=%s\n",
		cfg.Role, cfg.Proto, cfg.Encap, cfg.Iface, cfg.Entropy)

	if err := eng.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "sitg: %v\n", err)
		os.Exit(1)
	}
}
