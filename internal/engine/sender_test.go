package engine

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/jbemmel/sitg/internal/config"
	"github.com/jbemmel/sitg/internal/link"
	"github.com/jbemmel/sitg/internal/pattern"
	"github.com/jbemmel/sitg/internal/wire"
)

// Pause while transmitting the second packet of a message. The first packet
// expires while its ACK is queued, before the sender can return to its loop.
type delayedACKSocket struct {
	ack []byte
}

func (s *delayedACKSocket) SetNonblock(bool) error { return nil }
func (s *delayedACKSocket) Send(raw []byte) error {
	f, err := wire.ParseEthernetFrame(raw, 253)
	if err != nil {
		return err
	}
	opts := wire.BuildOpts{Encap: "udp4", SrcIP: f.DstIP, DstIP: f.SrcIP}
	if f.Proto == "mrc" {
		s.ack, err = wire.BuildMRCFrame(opts, wire.EncodeMRCSACK(f.QP, f.PSN+1, 0))
	} else {
		s.ack, err = wire.BuildUETFrame(opts, wire.EncodeUETSACK(f.QP, f.PSN+1, 0))
	}
	if f.PSN%2 == 1 {
		time.Sleep(5 * time.Millisecond)
	}
	return err
}
func (s *delayedACKSocket) Recv(buf []byte) (int, error) {
	if s.ack != nil {
		n := copy(buf, s.ack)
		s.ack = nil
		return n, nil
	}
	return 0, syscall.EAGAIN
}

func TestSenderAppliesQueuedACKBeforeExpiredTimer(t *testing.T) {
	for _, proto := range []string{"uet", "mrc"} {
		t.Run(proto, func(t *testing.T) { testQueuedACKBeforeExpiredTimer(t, proto) })
	}
}

func testQueuedACKBeforeExpiredTimer(t *testing.T, proto string) {
	t.Helper()
	cfg, err := config.Parse([]string{"--proto", proto, "--iface", "lo", "--encap", "udp4", "--dst", "127.0.0.2", "--dst-mac", "00:00:00:00:00:00", "--window", "2", "--pkt-size", "32", "--msg-size", "64", "--rto", "100us", "--duration", "1s", "--rate", "1Mbps"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Duration = 20 * time.Millisecond
	ep, err := link.ResolveEndpoint("lo")
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{cfg: cfg, sock: &delayedACKSocket{}, ep: ep, stats: NewStats("send"), dstMAC: make(map[netip.Addr]net.HardwareAddr), sel: pattern.New(cfg)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := e.runSend(ctx); err != nil {
		t.Fatal(err)
	}
	if e.stats.PacketsSent.Load() == 0 || e.stats.BytesAcked.Load() != e.stats.BytesSent.Load() {
		t.Fatal("transfer did not complete")
	}
	if got := e.stats.Retransmits.Load(); got != 0 {
		t.Fatalf("retransmitted %d packets despite queued ACKs", got)
	}
}

// A missing receiver must not turn the animation's 2pps into an RTO-rate flood.
type unacknowledgedSocket struct{ sent []time.Time }

func (s *unacknowledgedSocket) SetNonblock(bool) error   { return nil }
func (s *unacknowledgedSocket) Send([]byte) error        { s.sent = append(s.sent, time.Now()); return nil }
func (s *unacknowledgedSocket) Recv([]byte) (int, error) { return 0, syscall.EAGAIN }

func TestSingleProtocolRetriesRespectAnimationRate(t *testing.T) {
	for _, proto := range []string{"mrc", "uet"} {
		t.Run(proto, func(t *testing.T) {
			cfg, err := config.Parse([]string{"--proto", proto, "--iface", "lo", "--encap", "udp4", "--dst", "127.0.0.2", "--dst-mac", "00:00:00:00:00:00", "--pkt-size", "1200", "--msg-size", "1200", "--rate", "2pps", "--rto", "1ms", "--duration", "1s"})
			if err != nil {
				t.Fatal(err)
			}
			ep, err := link.ResolveEndpoint("lo")
			if err != nil {
				t.Fatal(err)
			}
			sock := &unacknowledgedSocket{}
			e := &Engine{cfg: cfg, sock: sock, ep: ep, stats: NewStats("send"), dstMAC: make(map[netip.Addr]net.HardwareAddr), sel: pattern.New(cfg)}
			ctx, cancel := context.WithTimeout(context.Background(), 1100*time.Millisecond)
			defer cancel()
			if err := e.runSend(ctx); err != nil {
				t.Fatal(err)
			}
			if len(sock.sent) < 2 || len(sock.sent) > 3 {
				t.Fatalf("2pps sent %d packets including retries", len(sock.sent))
			}
			if e.stats.Retransmits.Load() == 0 {
				t.Fatal("test did not exercise retries")
			}
			for i := 1; i < len(sock.sent); i++ {
				if gap := sock.sent[i].Sub(sock.sent[i-1]); gap < 450*time.Millisecond {
					t.Fatalf("unpaced retry after %s", gap)
				}
			}
		})
	}
}
