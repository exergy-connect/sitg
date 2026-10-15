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
	s.ack, err = wire.BuildUETFrame(wire.BuildOpts{Encap: "udp4", SrcIP: f.DstIP, DstIP: f.SrcIP}, wire.EncodeUETSACK(f.QP, f.PSN+1, 0))
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
	cfg, err := config.Parse([]string{"--iface", "lo", "--encap", "udp4", "--dst", "127.0.0.2", "--dst-mac", "00:00:00:00:00:00", "--window", "2", "--pkt-size", "32", "--msg-size", "64", "--rto", "100us", "--duration", "20ms", "--rate", "1Mbps"})
	if err != nil {
		t.Fatal(err)
	}
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
