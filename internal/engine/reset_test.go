package engine

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/jbemmel/sitg/internal/config"
	"github.com/jbemmel/sitg/internal/link"
	"github.com/jbemmel/sitg/internal/pattern"
	"github.com/jbemmel/sitg/internal/wire"
)

func TestSenderResetReceiverState(t *testing.T) {
	for _, proto := range []string{"uet", "mrc"} {
		t.Run(proto, func(t *testing.T) {
			cfg, err := config.Parse([]string{"--role", "recv", "--iface", "lo", "--proto", proto, "--encap", "udp4", "--sack-every", "1", "--duration", "0s"})
			if err != nil {
				t.Fatal(err)
			}
			cfg.FalconCMPort = falconTestPort(t, "127.0.0.2")
			sock := &receiverTestSocket{in: make(chan []byte, 16), out: make(chan []byte, 16)}
			receiver := &Engine{cfg: cfg, sock: sock, ep: &link.Endpoint{SrcIPv4: netip.MustParseAddr("127.0.0.2")}, stats: NewStats("recv")}
			startFalconTestReceiver(t, receiver)
			send := func(src string, psn uint32) uint32 {
				t.Helper()
				opts := wire.BuildOpts{Encap: "udp4", SrcIP: netip.MustParseAddr(src), DstIP: receiver.ep.SrcIPv4}
				var raw []byte
				var err error
				if proto == "uet" {
					raw, err = wire.BuildUETFrame(opts, wire.EncodeUETData(psn, 1, 1, 0, 4, false, []byte("test")))
				} else {
					raw, err = wire.BuildMRCFrame(opts, wire.EncodeMRCData(psn, 1, 1, 0, 4, false, []byte("test")))
				}
				if err != nil {
					t.Fatal(err)
				}
				sock.in <- raw
				select {
				case ack := <-sock.out:
					f, err := wire.ParseEthernetFrame(ack, 253)
					if err != nil {
						t.Fatal(err)
					}
					return f.CumAck
				case <-time.After(time.Second):
					t.Fatal("no ACK")
					return 0
				}
			}
			for _, src := range []string{"127.0.0.1", "127.0.0.3"} {
				for psn := uint32(0); psn < 3; psn++ {
					if got := send(src, psn); got != psn+1 {
						t.Fatalf("ACK=%d", got)
					}
				}
			}
			if got := send("127.0.0.1", 0); got != 3 {
				t.Fatalf("expected stale ACK 3, got %d", got)
			}
			senderCfg := *cfg
			senderCfg.Role = config.RoleSend
			senderCfg.Dst = receiver.ep.SrcIPv4
			sender := &Engine{cfg: &senderCfg, ep: &link.Endpoint{SrcIPv4: netip.MustParseAddr("127.0.0.1")}, sel: pattern.New(&senderCfg)}
			senderCfg.QP = 2
			if err := sender.resetReceivers(context.Background()); err == nil {
				t.Fatal("accepted wrong QP")
			}
			if got := send("127.0.0.1", 0); got != 3 {
				t.Fatalf("rejected reset changed state: %d", got)
			}
			senderCfg.QP = 1
			for i := 0; i < 2; i++ {
				if err := sender.resetReceivers(context.Background()); err != nil {
					t.Fatal(err)
				}
				if got := send("127.0.0.1", 0); got != 1 {
					t.Fatalf("reset ACK=%d, want 1", got)
				}
				if got := send("127.0.0.3", 0); got != 3 {
					t.Fatalf("reset affected another sender: ACK=%d", got)
				}
			}
		})
	}
}
