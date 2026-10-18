package engine

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jbemmel/sitg/internal/config"
	"github.com/jbemmel/sitg/internal/link"
	"github.com/jbemmel/sitg/internal/wire"
)

func reverseTestEngine(t *testing.T, planes []int) (*Engine, *receiverTestSocket, *mrcReversePeer) {
	t.Helper()
	paths := []netip.Addr{netip.MustParseAddr("5f00:0:100:301::"), netip.MustParseAddr("5f00:0:101:301::")}
	local, peer := netip.MustParseAddr("5f00:0:302::"), netip.MustParseAddr("5f00:0:301::")
	sock := &receiverTestSocket{out: make(chan []byte, 64)}
	e := &Engine{cfg: &config.Config{Proto: config.ProtoMRC, Role: config.RoleRecv, Encap: config.EncapUDP6, Entropy: config.EntropySRv6, Paths: 2, EVPlanes: planes, Window: 16, RTO: 10 * time.Millisecond, ReverseRTT: time.Millisecond, SackEvery: 1, QP: 1}, sock: sock, paths: paths,
		ep: &link.Endpoint{SrcIPv6: local, SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}}, stats: NewStats("recv"), dstMAC: map[netip.Addr]net.HardwareAddr{paths[0]: {2, 0, 0, 0, 0, 10}, paths[1]: {2, 0, 0, 0, 0, 11}}}
	return e, sock, e.reversePeer(mrcReverseKey{local, peer, "udp6", 1})
}
func nextReverseFrame(t *testing.T, s *receiverTestSocket) *wire.Frame {
	t.Helper()
	select {
	case raw := <-s.out:
		f, err := wire.ParseEthernetFrame(raw, 253)
		if err != nil {
			t.Fatal(err)
		}
		return f
	default:
		t.Fatal("no output frame")
		return nil
	}
}
func probeReply(p *mrcReversePeer, id uint16) *wire.Frame {
	return &wire.Frame{Proto: "mrc", Type: wire.TypeEVProbeReply, QP: 2, ProbeID: id, SrcIP: p.key.peer, DstIP: p.key.local, Encap: p.key.encap}
}
func TestReverseEVRequiresMatchedProbeAndSeparatesFeedback(t *testing.T) {
	e, s, p := reverseTestEngine(t, nil)
	now := time.Now()
	incoming := &wire.Frame{Proto: "mrc", Type: wire.TypeData, SrcIP: p.key.peer, DstIP: p.key.local, Encap: "udp6", QP: 1, PSN: 0, MRCEV: 0x12345678, Entropy: 0x5678, Payload: []byte("mrc")}
	if _, err := e.handleMRC(incoming, now); err != nil {
		t.Fatal(err)
	}
	probe := nextReverseFrame(t, s)
	if probe.Type != wire.TypeEVProbe || probe.QP != 2 {
		t.Fatalf("data ACK used an unconfirmed path: %+v", probe)
	}
	if len(s.out) != 0 || len(p.good) != 0 {
		t.Fatal("unconfirmed EV was promoted")
	}
	reply := probeReply(p, probe.ProbeID)
	wrong := *reply
	wrong.SrcIP = netip.MustParseAddr("2001:db8::bad")
	e.handleMRC(&wrong, now.Add(100*time.Microsecond))
	if len(p.good) != 0 {
		t.Fatal("wrong peer promoted EV")
	}
	wrong = *reply
	wrong.ProbeID++
	e.handleMRC(&wrong, now.Add(100*time.Microsecond))
	if len(p.good) != 0 {
		t.Fatal("unmatched ID promoted EV")
	}
	if _, err := e.handleMRC(reply, now.Add(100*time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	if len(p.good) != 1 {
		t.Fatal("matched reply did not confirm path")
	}
	if err := e.serviceMRC(now.Add(200 * time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	ack := nextReverseFrame(t, s)
	if ack.Type != wire.TypeSACK || ack.ReflectedEV != incoming.MRCEV || ack.MRCEV < 10000 || ack.MRCEV > 10001 || ack.AckPSN != 0 {
		t.Fatalf("reverse routing EV and reflected forward EV conflated: %+v", ack)
	}
	if e.paths[ack.MRCEV-10000] != ack.OuterDst {
		t.Fatal("routing EV does not identify ACK's uSID path")
	}
	if e.stats.EVProbesAcked.Load() != 1 {
		t.Fatal("probe not counted")
	}
}
func TestReverseEVPerPlaneAndRTTPacing(t *testing.T) {
	e, s, p := reverseTestEngine(t, []int{3, 7})
	now := time.Now()
	p.lastInbound = now
	for i := 0; i < 2; i++ {
		at := now.Add(time.Duration(i) * 2 * time.Millisecond)
		p.lastInbound = at
		if err := e.serviceMRC(at); err != nil {
			t.Fatal(err)
		}
		f := nextReverseFrame(t, s)
		if f.MRCEV != uint32(10000+i) {
			t.Fatalf("plane not probed: %+v", f)
		}
		e.handleMRC(probeReply(p, f.ProbeID), at.Add(100*time.Microsecond))
	}
	if len(p.good) != 2 {
		t.Fatal("not one confirmed EV per plane")
	}
	if err := e.serviceMRC(now.Add(2200 * time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	if len(s.out) != 0 {
		t.Fatal("more than one probe per RTT")
	}
	p.lastOutbound = now.Add(3 * time.Millisecond)
	p.lastInbound = p.lastOutbound
	if err := e.serviceMRC(p.lastOutbound); err != nil {
		t.Fatal(err)
	}
	if len(s.out) != 0 {
		t.Fatal("outbound data should supply SACK feedback instead of probes")
	}
	if err := e.serviceMRC(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(s.out) != 0 {
		t.Fatal("inactive inbound QP keeps probing")
	}
}
func TestReverseEVLostProbeCannotPromoteOrRetainStalePath(t *testing.T) {
	e, s, p := reverseTestEngine(t, nil)
	now := time.Now()
	p.lastInbound = now
	e.serviceMRC(now)
	f := nextReverseFrame(t, s)
	e.handleMRC(probeReply(p, f.ProbeID), now.Add(time.Second))
	if len(p.good) != 0 {
		t.Fatal("late probe response promoted candidate")
	}
	e.serviceMRC(now.Add(time.Second))
	if len(e.mrcProbes) != 0 {
		t.Fatal("lost probe leaked pending state")
	}
	p.good[0] = mrcProof{0, now}
	if _, ok := e.confirmedPath(p, now.Add(time.Second)); ok {
		t.Fatal("stale reverse EV remains selectable")
	}
}
func TestReverseEVRefreshFromDataSACKAndRejectMarkedFeedback(t *testing.T) {
	e, s, p := reverseTestEngine(t, nil)
	now := time.Now()
	opts, err := e.mrcOpts(p.key, 1)
	if err != nil {
		t.Fatal(err)
	}
	e.noteMRCData(opts, 1, 5, now)
	ack := &wire.Frame{Proto: "mrc", Type: wire.TypeSACK, QP: 1, SrcIP: p.key.peer, DstIP: p.key.local, Encap: "udp6", CumAck: 6, AckPSN: 5, ReflectedEV: 10001, MRCEV: 9999}
	e.noteMRCSACK(ack, now.Add(100*time.Microsecond))
	if p.good[0].path != 1 || p.good[0].at.IsZero() {
		t.Fatal("forward data SACK did not refresh reverse EV")
	}
	p.lastInbound = now.Add(200 * time.Microsecond)
	e.serviceMRC(p.lastInbound)
	if len(s.out) != 0 {
		t.Fatal("bidirectional data feedback should suppress probes")
	}
	e.noteMRCData(opts, 1, 6, now.Add(time.Millisecond))
	ack.CumAck = 7
	ack.AckPSN = 6
	ack.Congestion = 1
	e.noteMRCSACK(ack, now.Add(1100*time.Microsecond))
	if len(p.good) != 0 {
		t.Fatal("ECN-marked SACK retained a healthy reverse proof")
	}
}
func TestReverseEVBidirectionalBootstrapStillProbes(t *testing.T) {
	e, s, p := reverseTestEngine(t, nil)
	now := time.Now()
	p.lastInbound = now
	p.lastOutbound = now
	e.serviceMRC(now)
	if nextReverseFrame(t, s).Type != wire.TypeEVProbe {
		t.Fatal("bidirectional startup deadlocked waiting for SACK proofs")
	}
}

func TestReverseEVUnacknowledgedPlaneNeverCarriesControl(t *testing.T) {
	e, s, p := reverseTestEngine(t, []int{0, 1})
	now := time.Now()
	p.lastInbound = now
	e.serviceMRC(now)
	first := nextReverseFrame(t, s)
	e.handleMRC(probeReply(p, first.ProbeID), now.Add(100*time.Microsecond))
	p.lastInbound = now.Add(2 * time.Millisecond)
	e.serviceMRC(p.lastInbound)
	lost := nextReverseFrame(t, s)
	if lost.MRCEV != 10001 {
		t.Fatal("second plane not probed")
	}
	for i := 0; i < 8; i++ {
		path, ok := e.confirmedPath(p, now.Add(3*time.Millisecond))
		if !ok || path != 0 {
			t.Fatal("unacknowledged plane used for controls")
		}
	}
	e.handleMRC(probeReply(p, lost.ProbeID), now.Add(3*time.Millisecond))
	if len(p.good) != 2 {
		t.Fatal("recovered plane was not promoted after its probe reply")
	}
}

func TestReverseEVNACKInvalidatesOnlyMatchingSentEV(t *testing.T) {
	e, _, p := reverseTestEngine(t, nil)
	now := time.Now()
	opts, err := e.mrcOpts(p.key, 0)
	if err != nil {
		t.Fatal(err)
	}
	e.noteMRCData(opts, 1, 9, now)
	p.good[0] = mrcProof{0, now}
	nack := &wire.Frame{Proto: "mrc", Type: wire.TypeNACK, QP: 1, PSN: 9, ReflectedEV: 10001, SrcIP: p.key.peer, DstIP: p.key.local, Encap: "udp6"}
	e.handleMRC(nack, now.Add(100*time.Microsecond))
	if len(p.good) != 1 {
		t.Fatal("mismatched NACK invalidated another EV")
	}
	nack.ReflectedEV = 10000
	e.handleMRC(nack, now.Add(100*time.Microsecond))
	if len(p.good) != 0 {
		t.Fatal("matching NACK left reverse EV selectable")
	}
}

func TestEndpointProbeReplyUsesConfirmedRouteFromAnyQP(t *testing.T) {
	e, s, p := reverseTestEngine(t, nil)
	now := time.Now()
	delete(e.mrcReverse, p.key)
	key := p.key
	key.qp = 42
	peer := e.reversePeer(key)
	peer.good[0] = mrcProof{0, now}
	request := &wire.Frame{Proto: "mrc", Type: wire.TypeEVProbe, QP: 2, ProbeID: 17, SrcIP: key.peer, DstIP: key.local, Encap: key.encap}
	if handled, err := e.handleMRC(request, now); !handled || err != nil {
		t.Fatalf("probe not handled: %v", err)
	}
	reply := nextReverseFrame(t, s)
	if reply.Type != wire.TypeEVProbeReply || reply.ProbeID != 17 || reply.QP != 2 || reply.OuterDst != e.paths[0] {
		t.Fatalf("node-scope probe response ignored confirmed QP route: %+v", reply)
	}
}
