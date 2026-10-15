package engine

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/jbemmel/sitg/internal/config"
	"github.com/jbemmel/sitg/internal/wire"
)

type mixedRecordingSocket struct {
	packetSocket
	frames []*wire.Frame
}

func (s *mixedRecordingSocket) Send(raw []byte) error {
	f, err := wire.ParseEthernetFrame(raw, 253)
	if err != nil {
		return err
	}
	s.frames = append(s.frames, f)
	return s.packetSocket.Send(raw)
}

func TestMixedSwitchAndReliability(t *testing.T) {
	for _, threshold := range []string{"3packets", "300B", "2400b", "10ms"} {
		t.Run(threshold, func(t *testing.T) {
			n := &falconTestNetwork{sockets: make(map[netip.Addr]*falconTestSocket), dropData: true}
			receiver := newFalconTestEngine(t, n, "127.0.0.2", "--proto", "all", "--encap", "udp4")
			receiver.cfg.FalconCMPort = falconTestPort(t, "127.0.0.2")
			startFalconTestReceiver(t, receiver)
			sender := newFalconTestEngine(t, n, "127.0.0.1", "--role", "send", "--proto", "mixed", "--dst", "127.0.0.2", "--dst-mac", "02:00:00:00:00:02", "--switch-every", threshold, "--duration", "100ms", "--rate", "1Mbps", "--rto", "10ms")
			sender.cfg.FalconCMPort = receiver.cfg.FalconCMPort
			record := &mixedRecordingSocket{packetSocket: sender.sock}
			sender.sock = record
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := sender.runSend(ctx); err != nil {
				t.Fatal(err)
			}
			type key struct {
				proto string
				psn   uint32
			}
			seen := make(map[key]bool)
			counts := make(map[string]int)
			var bytes, phaseBytes uint64
			phasePackets, index, phases := 0, 0, 0
			for _, f := range record.frames {
				k := key{f.Proto, f.PSN}
				if seen[k] {
					continue
				}
				seen[k] = true
				if f.Proto != string(mixedProtocols[index]) {
					if sender.cfg.SwitchEvery.Packets > 0 && phasePackets != 3 {
						t.Fatalf("phase has %d packets", phasePackets)
					}
					if sender.cfg.SwitchEvery.Bytes > 0 && phaseBytes != 300 {
						t.Fatalf("phase has %d bytes", phaseBytes)
					}
					index = (index + 1) % 3
					if f.Proto != string(mixedProtocols[index]) {
						t.Fatalf("unexpected protocol %s", f.Proto)
					}
					phasePackets, phaseBytes = 0, 0
					phases++
				}
				phasePackets++
				phaseBytes += uint64(len(f.Payload))
				bytes += uint64(len(f.Payload))
				counts[f.Proto]++
			}
			if phases < 3 || len(counts) != 3 {
				t.Fatalf("did not complete a cycle: phases=%d counts=%v", phases, counts)
			}
			if sender.stats.BytesAcked.Load() != bytes || receiver.stats.BytesUnique.Load() != bytes {
				t.Fatalf("lost bytes: sent=%d acked=%d received=%d", bytes, sender.stats.BytesAcked.Load(), receiver.stats.BytesUnique.Load())
			}
			if sender.stats.Retransmits.Load() == 0 {
				t.Fatal("dropped packet was not retried")
			}
		})
	}
}

func TestMixedTimeSwitch(t *testing.T) {
	start := time.Now()
	p := mixedPhase{start: start}
	limit := config.SwitchLimit{Interval: time.Second}
	if p.advance(limit, start.Add(999*time.Millisecond)) {
		t.Fatal("switched early")
	}
	if !p.advance(limit, start.Add(time.Second)) || p.index != 1 {
		t.Fatal("did not switch on interval")
	}
}
