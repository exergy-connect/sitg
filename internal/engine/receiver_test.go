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
	"github.com/jbemmel/sitg/internal/wire"
)

type receiverTestSocket struct{ in, out chan []byte }

func (s *receiverTestSocket) SetNonblock(bool) error { return nil }
func (s *receiverTestSocket) Recv(buf []byte) (int, error) {
	select {
	case b := <-s.in:
		return copy(buf, b), nil
	default:
		return 0, syscall.EAGAIN
	}
}
func (s *receiverTestSocket) Send(b []byte) error { s.out <- append([]byte(nil), b...); return nil }

func TestReceiveAllProtocolsAndVariants(t *testing.T) {
	cfg, err := config.Parse([]string{"--role", "recv", "--iface", "lo", "--proto", "all", "--qp", "7", "--pkt-size", "256", "--msg-size", "1KiB", "--sack-every", "1", "--duration", "0s"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.FalconCMPort = falconTestPort(t, "127.0.0.2")
	sock := &receiverTestSocket{in: make(chan []byte, 64), out: make(chan []byte, 64)}
	e := &Engine{cfg: cfg, sock: sock, ep: &link.Endpoint{SrcIPv4: netip.MustParseAddr("127.0.0.2"), SrcIPv6: netip.MustParseAddr("::1"), SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}}, stats: NewStats("recv")}
	startFalconTestReceiver(t, e)
	// Both address-family listeners negotiate Falcon connections while the same
	// raw socket also receives UET and MRC, including native and SRv6 variants.
	n := &falconTestNetwork{sockets: make(map[netip.Addr]*falconTestSocket)}
	s4 := newFalconTestEngine(t, n, "127.0.0.1")
	s6 := newFalconTestEngine(t, n, "::1", "--encap", "udp6")
	s4.cfg.FalconCMPort = cfg.FalconCMPort
	s6.cfg.FalconCMPort = cfg.FalconCMPort
	c4, err := s4.dialFalcon(context.Background(), e.ep.SrcIPv4, 55)
	if err != nil {
		t.Fatal(err)
	}
	defer c4.cm.Close()
	c6, err := s6.dialFalcon(context.Background(), e.ep.SrcIPv6, 66)
	if err != nil {
		t.Fatal(err)
	}
	defer c6.cm.Close()
	type expected struct {
		proto, encap string
		qp, cum      uint32
	}
	var want []expected
	var first []byte
	for _, proto := range []string{"uet", "mrc", "falcon"} {
		for _, encap := range []string{"udp4", "udp6", "ip4", "ip6"} {
			if proto != "uet" && (encap == "ip4" || encap == "ip6") {
				continue
			}
			for variant := 0; variant < 2; variant++ {
				opts := wire.BuildOpts{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: e.ep.SrcMAC, Encap: encap, IPProto: cfg.IPProto, Entropy: uint16(10000 + variant), UseSRv6: variant == 1, SRv6SrcIP: netip.MustParseAddr("2001:db8::1"), SRv6Dst: netip.MustParseAddr("fc00::1")}
				conn := c6
				opts.SrcIP, opts.DstIP = s6.ep.SrcIPv6, e.ep.SrcIPv6
				if encap == "udp4" || encap == "ip4" {
					conn = c4
					opts.SrcIP, opts.DstIP = s4.ep.SrcIPv4, e.ep.SrcIPv4
				}
				var raw []byte
				qp, cum := uint32(7), uint32(1)
				switch proto {
				case "uet":
					raw, err = wire.BuildUETFrame(opts, wire.EncodeUETData(0, 7, 1, 0, 4, false, []byte("test")))
				case "mrc":
					raw, err = wire.BuildMRCFrame(opts, wire.EncodeMRCData(0, 7, 1, 0, 4, false, []byte("test")))
				case "falcon":
					raw, err = wire.BuildFalconFrame(opts, wire.EncodeFalconData(uint32(variant), conn.remoteCID, 1, []byte("test")))
					qp = conn.localCID
					cum = uint32(variant + 1)
				}
				if err != nil {
					t.Fatal(err)
				}
				if first == nil {
					first = raw
				}
				sock.in <- raw
				want = append(want, expected{proto, encap, qp, cum})
			}
		}
	}
	other, err := wire.BuildUETFrame(wire.BuildOpts{SrcIP: netip.MustParseAddr("127.0.0.3"), DstIP: e.ep.SrcIPv4, Encap: "udp4"}, wire.EncodeUETData(0, 7, 1, 0, 4, false, []byte("peer")))
	if err != nil {
		t.Fatal(err)
	}
	sock.in <- other
	want = append(want, expected{"uet", "udp4", 7, 1})
	// The same initial PSN in different protocols/encapsulations/variants must
	// count as unique data; a repeat within one flow must count as a duplicate.
	sock.in <- first
	want = append(want, want[0])
	for i, w := range want {
		select {
		case raw := <-sock.out:
			f, err := wire.ParseEthernetFrame(raw, cfg.IPProto)
			if err != nil {
				t.Fatal(err)
			}
			if f.Type != wire.TypeSACK || f.Proto != w.proto || f.Encap != w.encap || f.QP != w.qp || f.CumAck != w.cum || f.Bitmap != 0 {
				t.Fatalf("ACK %d: %+v want %+v", i, f, w)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("missing ACK %d for %+v", i, w)
		}
	}
	if e.stats.BytesUnique.Load() != 68 || e.stats.PacketsRecv.Load() != 18 || e.stats.Duplicates.Load() != 1 {
		t.Fatalf("unique=%d packets=%d dup=%d", e.stats.BytesUnique.Load(), e.stats.PacketsRecv.Load(), e.stats.Duplicates.Load())
	}
}

func TestReceiverFiltersAndSingleAddressFamily(t *testing.T) {
	for _, proto := range []string{"uet", "mrc"} {
		cfg, err := config.Parse([]string{"--role", "recv", "--iface", "lo", "--proto", proto, "--encap", "udp4", "--qp", "7", "--sack-every", "1", "--duration", "0s"})
		if err != nil {
			t.Fatal(err)
		}
		sock := &receiverTestSocket{in: make(chan []byte, 16), out: make(chan []byte, 16)}
		e := &Engine{cfg: cfg, sock: sock, ep: &link.Endpoint{SrcIPv4: netip.MustParseAddr("127.0.0.2")}, stats: NewStats("recv")}
		if len(e.receiverIPs()) != 1 {
			t.Fatal("IPv4-only interface requires IPv6")
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- e.runRecv(ctx) }()
		// Queue a different protocol, QP, encapsulation, and destination before one
		// matching frame, so its ACK proves the preceding filters have been applied.
		for i := 0; i < 5; i++ {
			opts := wire.BuildOpts{SrcIP: netip.MustParseAddr("127.0.0.1"), DstIP: e.ep.SrcIPv4, Encap: "udp4", IPProto: 253}
			p, qp := proto, uint32(7)
			if i == 0 {
				if p == "uet" {
					p = "mrc"
				} else {
					p = "uet"
				}
			}
			if i == 1 {
				qp = 8
			}
			if i == 2 {
				opts.Encap = "udp6"
				opts.SrcIP = netip.MustParseAddr("::1")
				opts.DstIP = netip.MustParseAddr("::2")
			}
			if i == 3 {
				opts.DstIP = netip.MustParseAddr("127.0.0.99")
			}
			var b []byte
			if p == "uet" {
				b, err = wire.BuildUETFrame(opts, wire.EncodeUETData(0, qp, 1, 0, 1, false, []byte{1}))
			} else {
				b, err = wire.BuildMRCFrame(opts, wire.EncodeMRCData(0, qp, 1, 0, 1, false, []byte{1}))
			}
			if err != nil {
				t.Fatal(err)
			}
			sock.in <- b
		}
		select {
		case <-sock.out:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("no matching ACK")
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if e.stats.PacketsRecv.Load() != 1 {
			t.Fatalf("%s accepted filtered packets", proto)
		}
	}
}

func TestReceiverAllWithOneAddressFamily(t *testing.T) {
	for _, ip := range []string{"127.0.0.2", "::1"} {
		t.Run(ip, func(t *testing.T) {
			n := &falconTestNetwork{sockets: make(map[netip.Addr]*falconTestSocket)}
			receiver := newFalconTestEngine(t, n, ip, "--proto", "all", "--encap", "all")
			receiver.cfg.FalconCMPort = falconTestPort(t, ip)
			startFalconTestReceiver(t, receiver)
			encap, clientIP := "udp4", "127.0.0.1"
			if ip == "::1" {
				encap, clientIP = "udp6", "::1"
			}
			sender := newFalconTestEngine(t, n, clientIP, "--encap", encap)
			sender.cfg.FalconCMPort = receiver.cfg.FalconCMPort
			conn, err := sender.dialFalcon(context.Background(), netip.MustParseAddr(ip), 55)
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.cm.Close()
		})
	}
}

func TestReceiverACKCyclesExplicitSRv6Paths(t *testing.T) {
	paths := []netip.Addr{netip.MustParseAddr("5f00:0:100:301::"), netip.MustParseAddr("5f00:0:101:301::")}
	local := netip.MustParseAddr("5f00:0:302::")
	peer := netip.MustParseAddr("5f00:0:301::")
	sock := &receiverTestSocket{out: make(chan []byte, 3)}
	e := &Engine{
		cfg:  &config.Config{Role: config.RoleRecv, Encap: config.EncapAll, Entropy: config.EntropySRv6},
		sock: sock, ep: &link.Endpoint{SrcIPv6: local, SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}},
		paths: paths, stats: NewStats("recv"),
		dstMAC: map[netip.Addr]net.HardwareAddr{
			paths[0]: {2, 0, 0, 0, 0, 10}, paths[1]: {2, 0, 0, 0, 0, 11},
		},
	}
	c := &falconConnection{localIP: local, peer: peer, encap: "udp6", remoteCID: 1, tracker: NewRecvTracker(), last: &wire.Frame{Proto: "mrc", Entropy: 10000}}
	c.tracker.Observe(0)
	for i := 0; i < 3; i++ {
		if err := e.receiverACK(c); err != nil {
			t.Fatal(err)
		}
		frame, err := wire.ParseEthernetFrame(<-sock.out, 253)
		if err != nil {
			t.Fatal(err)
		}
		if !frame.OuterSRv6 || frame.OuterDst != paths[i%2] || frame.SrcIP != local || frame.DstIP != peer || frame.Type != wire.TypeSACK || frame.CumAck != 1 {
			t.Fatalf("wrong routed ACK %d: %+v", i, frame)
		}
	}
}
