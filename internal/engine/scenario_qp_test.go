package engine

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestScenarioSectionsWithDistinctQPs(t *testing.T) {
	n := &falconTestNetwork{sockets: make(map[netip.Addr]*falconTestSocket)}
	receiver := newFalconTestEngine(t, n, "127.0.0.2", "--proto", "all", "--encap", "all", "--accept-any-qp")
	receiver.cfg.FalconCMPort = falconTestPort(t, "127.0.0.2")
	startFalconTestReceiver(t, receiver)
	for i, proto := range []string{"mrc", "mrc", "mixed", "uet", "mixed", "falcon", "mixed", "mixed", "mixed", "mixed"} {
		sender := newFalconTestEngine(t, n, "127.0.0.1", "--role", "send", "--proto", proto, "--encap", "udp4", "--dst", "127.0.0.2", "--dst-mac", "02:00:00:00:00:02", "--duration", "1s", "--rate", "1000pps", "--switch-every", "5ms", "--rto", "20ms")
		sender.cfg.Duration = 40 * time.Millisecond
		sender.cfg.QP = uint32(100 + i)
		sender.cfg.FalconCMPort = receiver.cfg.FalconCMPort
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := sender.runSend(ctx)
		cancel()
		if err != nil {
			t.Fatalf("section %d %s: %v", i, proto, err)
		}
		if sender.stats.BytesAcked.Load() == 0 {
			t.Fatalf("section %d %s made no acknowledged progress", i, proto)
		}
	}
	if receiver.stats.Duplicates.Load() != 0 {
		t.Fatal("new QPs treated as duplicate streams")
	}
}
