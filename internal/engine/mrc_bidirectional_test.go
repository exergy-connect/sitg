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

type mrcDuplexSocket struct {
	in    chan []byte
	peers map[netip.Addr]*mrcDuplexSocket
}

func (s *mrcDuplexSocket) SetNonblock(bool) error { return nil }
func (s *mrcDuplexSocket) Recv(buf []byte) (int, error) {
	select {
	case raw := <-s.in:
		return copy(buf, raw), nil
	default:
		return 0, syscall.EAGAIN
	}
}
func (s *mrcDuplexSocket) Send(raw []byte) error {
	f, err := wire.ParseEthernetFrame(raw, 253)
	if err != nil {
		return err
	}
	if peer := s.peers[f.DstIP]; peer != nil {
		peer.in <- append([]byte(nil), raw...)
	}
	return nil
}
func TestMRCBidirectionalDataRefreshesReverseEVs(t *testing.T) {
	a, b := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
	sa, sb := &mrcDuplexSocket{in: make(chan []byte, 4096)}, &mrcDuplexSocket{in: make(chan []byte, 4096)}
	peers := map[netip.Addr]*mrcDuplexSocket{a: sa, b: sb}
	sa.peers, sb.peers = peers, peers
	makeEngine := func(local, peer netip.Addr, sock *mrcDuplexSocket) *Engine {
		cfg, err := config.Parse([]string{"--role", "send", "--iface", "lo", "--proto", "mrc", "--encap", "udp4", "--dst", peer.String(), "--entropy", "srv6", "--srv6-paths", "5f00:0:100:301::,5f00:0:101:301::", "--dst-mac", "02:00:00:00:00:02", "--rate", "1000pps", "--pkt-size", "64", "--msg-size", "64", "--sack-every", "1", "--rto", "50ms", "--duration", "1s"})
		if err != nil {
			t.Fatal(err)
		}
		return &Engine{cfg: cfg, sock: sock, ep: &link.Endpoint{SrcIPv4: local, SrcIPv6: netip.IPv6Loopback(), SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}}, stats: NewStats("send"), paths: append([]netip.Addr(nil), cfg.SRv6Paths...), dstMAC: make(map[netip.Addr]net.HardwareAddr), sel: pattern.New(cfg)}
	}
	ea, eb := makeEngine(a, b, sa), makeEngine(b, a, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	done := make(chan error, 2)
	go func() { done <- ea.RunContext(ctx) }()
	go func() { done <- eb.RunContext(ctx) }()
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []*Engine{ea, eb} {
		if e.stats.BytesAcked.Load() == 0 || e.stats.PacketsRecv.Load() == 0 {
			t.Fatal("bidirectional data did not flow")
		}
		if e.stats.ReverseEVDataUpdates.Load() == 0 {
			t.Fatal("outbound data SACKs did not refresh reverse EVs")
		}
		var healthy bool
		for _, p := range e.mrcReverse {
			healthy = healthy || len(p.good) > 0
		}
		if !healthy {
			t.Fatal("data SACKs did not maintain a reverse EV")
		}
	}
}
