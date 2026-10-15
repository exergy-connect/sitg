package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jbemmel/sitg/internal/config"
	"github.com/jbemmel/sitg/internal/link"
	"github.com/jbemmel/sitg/internal/pattern"
	"github.com/jbemmel/sitg/internal/wire"
)

type falconTestNetwork struct {
	mu       sync.Mutex
	sockets  map[netip.Addr]*falconTestSocket
	dropped  bool
	dropData bool
	sent     atomic.Uint64
}
type falconTestSocket struct {
	network *falconTestNetwork
	packets chan []byte
}

func (s *falconTestSocket) SetNonblock(bool) error { return nil }
func (s *falconTestSocket) Recv(buf []byte) (int, error) {
	select {
	case b := <-s.packets:
		return copy(buf, b), nil
	default:
		return 0, syscall.EAGAIN
	}
}
func (s *falconTestSocket) Send(b []byte) error {
	f, err := wire.ParseEthernetFrame(b, 253)
	if err != nil {
		return err
	}
	s.network.sent.Add(1)
	s.network.mu.Lock()
	defer s.network.mu.Unlock()
	if s.network.dropData && !s.network.dropped && f.Type == wire.TypeData && f.PSN == 0 {
		s.network.dropped = true
		return nil
	}
	dst := s.network.sockets[f.DstIP]
	if dst == nil {
		return fmt.Errorf("no test endpoint %s", f.DstIP)
	}
	select {
	case dst.packets <- append([]byte(nil), b...):
		return nil
	default:
		return fmt.Errorf("test queue full")
	}
}

func newFalconTestEngine(t *testing.T, n *falconTestNetwork, ip string, args ...string) *Engine {
	t.Helper()
	base := []string{"--role", "recv", "--iface", "lo", "--proto", "falcon", "--encap", "udp4", "--qp", "7", "--pkt-size", "256", "--msg-size", "1KiB", "--window", "8", "--sack-every", "1", "--rto", "2ms", "--duration", "0s", "--connect-timeout", "1s"}
	cfg, err := config.Parse(append(base, args...))
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr(ip)
	sock := &falconTestSocket{network: n, packets: make(chan []byte, 4096)}
	n.mu.Lock()
	n.sockets[addr] = sock
	n.mu.Unlock()
	ipv4, ipv6 := netip.Addr{}, netip.Addr{}
	if addr.Is4() {
		ipv4 = addr
	} else {
		ipv6 = addr
	}
	return &Engine{cfg: cfg, sock: sock, ep: &link.Endpoint{SrcIPv4: ipv4, SrcIPv6: ipv6, SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}}, stats: NewStats(string(cfg.Role)), dstMAC: make(map[netip.Addr]net.HardwareAddr), sel: pattern.New(cfg)}
}

func falconTestPort(t *testing.T, ip string) int {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}
func awaitFalcon(t *testing.T, condition func() bool) {
	t.Helper()
	end := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(end) {
			t.Fatal("timed out waiting for Falcon state")
		}
		time.Sleep(time.Millisecond)
	}
}
func startFalconTestReceiver(t *testing.T, e *Engine) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.runRecv(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("receiver did not stop")
		}
	})
	ips := e.receiverIPs()
	if len(ips) == 0 {
		t.Fatal("no receiver address")
	}
	addr := net.JoinHostPort(ips[0].String(), strconv.Itoa(e.cfg.FalconCMPort))
	awaitFalcon(t, func() bool {
		c, err := net.DialTimeout("tcp", addr, 10*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})
}

func TestFalconSetupDirectionalCIDsAndDataGate(t *testing.T) {
	n := &falconTestNetwork{sockets: make(map[netip.Addr]*falconTestSocket)}
	receiver := newFalconTestEngine(t, n, "127.0.0.2")
	receiver.cfg.FalconCMPort = falconTestPort(t, "127.0.0.2")
	startFalconTestReceiver(t, receiver)
	sender := newFalconTestEngine(t, n, "127.0.0.1", "--pkt-size", "512", "--window", "16")
	sender.cfg.FalconCMPort = receiver.cfg.FalconCMPort
	opts := wire.BuildOpts{SrcIP: sender.ep.SrcIPv4, DstIP: receiver.ep.SrcIPv4, Encap: "udp4"}
	send := func(cid, psn uint32) {
		t.Helper()
		b, err := wire.BuildFalconFrame(opts, wire.EncodeFalconData(psn, cid, 1, []byte("abc")))
		if err != nil {
			t.Fatal(err)
		}
		if err := sender.sock.Send(b); err != nil {
			t.Fatal(err)
		}
	}
	// A data packet addressed to the future receive CID cannot create a connection.
	send(7, 0)
	time.Sleep(10 * time.Millisecond)
	if receiver.stats.PacketsRecv.Load() != 0 {
		t.Fatal("accepted data before setup")
	}
	c, err := sender.dialFalcon(context.Background(), receiver.ep.SrcIPv4, 42)
	if err != nil {
		t.Fatal(err)
	}
	defer c.cm.Close()
	if c.localCID != 42 || c.remoteCID != 7 || c.payload != 256 || c.window.capacity != 8 {
		t.Fatalf("bad negotiation: %+v", c)
	}
	send(c.remoteCID, 0)
	awaitFalcon(t, func() bool { return receiver.stats.BytesUnique.Load() == 3 })
	var ack *wire.Frame
	awaitFalcon(t, func() bool {
		buf := make([]byte, 65536)
		sz, err := sender.sock.Recv(buf)
		if err != nil {
			return false
		}
		ack, err = wire.ParseEthernetFrame(buf[:sz], 253)
		return err == nil
	})
	if ack.QP != 42 || ack.CumAck != 1 {
		t.Fatalf("ACK did not use initiator's receive CID: %+v", ack)
	}
	// An independent connection starts at PSN zero without resetting the first.
	second, err := sender.dialFalcon(context.Background(), receiver.ep.SrcIPv4, 43)
	if err != nil {
		t.Fatal(err)
	}
	defer second.cm.Close()
	if second.remoteCID == c.remoteCID {
		t.Fatal("receiver reused a live CID")
	}
	send(second.remoteCID, 0)
	awaitFalcon(t, func() bool { return receiver.stats.BytesUnique.Load() == 6 })
	// Closing the CM association removes its receive CID. Reconnect with the same
	// initiator CID only after the old association has been removed.
	_ = c.cm.Close()
	sender.cfg.Window = 2
	var reconnected *falconConnection
	awaitFalcon(t, func() bool {
		var err error
		reconnected, err = sender.dialFalcon(context.Background(), receiver.ep.SrcIPv4, 42)
		return err == nil
	})
	defer reconnected.cm.Close()
	if reconnected.remoteCID == c.remoteCID {
		t.Fatal("reused retired CID")
	}
	send(c.remoteCID, 1) // stale connection
	opts.SrcIP = netip.MustParseAddr("127.0.0.99")
	send(reconnected.remoteCID, 0) // wrong peer identity
	opts.SrcIP = sender.ep.SrcIPv4
	send(reconnected.remoteCID, 2) // outside negotiated two-packet window
	send(reconnected.remoteCID, 0)
	awaitFalcon(t, func() bool { return receiver.stats.BytesUnique.Load() >= 9 })
	if receiver.stats.BytesUnique.Load() != 9 || receiver.stats.PacketsRecv.Load() != 3 {
		t.Fatal("accepted stale, wrong-peer or out-of-window data")
	}

}

func TestFalconConcurrentIncastFanoutAndRetransmission(t *testing.T) {
	n := &falconTestNetwork{sockets: make(map[netip.Addr]*falconTestSocket), dropData: true}
	port := falconTestPort(t, "127.0.0.2")
	r1 := newFalconTestEngine(t, n, "127.0.0.2")
	r2 := newFalconTestEngine(t, n, "127.0.0.3", "--pkt-size", "128")
	r1.cfg.FalconCMPort = port
	r2.cfg.FalconCMPort = port
	startFalconTestReceiver(t, r1)
	startFalconTestReceiver(t, r2)
	s1 := newFalconTestEngine(t, n, "127.0.0.1", "--role", "send", "--pattern", "outcast", "--peers", "127.0.0.2,127.0.0.3", "--dst-mac", "02:00:00:00:00:01", "--rate", "1Mbps", "--duration", "1s")
	s2 := newFalconTestEngine(t, n, "127.0.0.4", "--role", "send", "--dst", "127.0.0.2", "--dst-mac", "02:00:00:00:00:01", "--rate", "1Mbps", "--duration", "1s")
	s1.cfg.Duration = 100 * time.Millisecond
	s2.cfg.Duration = 100 * time.Millisecond
	s1.cfg.FalconCMPort = port
	s2.cfg.FalconCMPort = port
	done := make(chan error, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { done <- s1.runSend(ctx) }()
	go func() { done <- s2.runSend(ctx) }()
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if ctx.Err() != nil {
		t.Fatal("sender failed to drain")
	}
	totalAck := s1.stats.BytesAcked.Load() + s2.stats.BytesAcked.Load()
	totalSent := s1.stats.BytesSent.Load() + s2.stats.BytesSent.Load()
	unique := r1.stats.BytesUnique.Load() + r2.stats.BytesUnique.Load()
	if totalAck == 0 || totalAck != unique || totalSent <= totalAck {
		t.Fatalf("sent=%d acked=%d unique=%d", totalSent, totalAck, unique)
	}
	if s1.stats.Retransmits.Load()+s2.stats.Retransmits.Load() == 0 {
		t.Fatal("dropped packet was not retransmitted")
	}
	if r1.stats.BytesUnique.Load() == 0 || r2.stats.BytesUnique.Load() == 0 {
		t.Fatal("fanout did not reach both peers")
	}
}

func TestFalconCMRejectAndTimeout(t *testing.T) {
	n := &falconTestNetwork{sockets: make(map[netip.Addr]*falconTestSocket)}
	receiver := newFalconTestEngine(t, n, "127.0.0.2")
	receiver.cfg.FalconCMPort = falconTestPort(t, "127.0.0.2")
	startFalconTestReceiver(t, receiver)
	sender := newFalconTestEngine(t, n, "127.0.0.1", "--qp", "8", "--role", "send", "--dst", "127.0.0.2")
	sender.cfg.FalconCMPort = receiver.cfg.FalconCMPort
	if c, err := sender.dialFalcon(context.Background(), receiver.ep.SrcIPv4, 8); err == nil {
		_ = c.cm.Close()
		t.Fatal("accepted wrong service")
	}
	// A nonresponsive control plane must time out before any raw data is sent.
	listener, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		c, err := listener.Accept()
		if err == nil {
			defer c.Close()
			var b [4096]byte
			for {
				if _, err := c.Read(b[:]); err != nil {
					return
				}
			}
		}
	}()
	sender.cfg.FalconCMPort = listener.Addr().(*net.TCPAddr).Port
	sender.cfg.ConnectTimeout = 30 * time.Millisecond
	if err := sender.runSend(context.Background()); err == nil {
		t.Fatal("setup did not time out")
	}
	<-serverDone
	if n.sent.Load() != 0 {
		t.Fatal("data sent during failed setup")
	}
}

func TestFalconCMTeardownAndValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	events := make(chan falconCMEvent)
	go serveFalconCM(ctx, l, time.Second, events)
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h := falconHello{Protocol: falconCMVersion, CID: 12, Service: 7, Encap: "udp4", Payload: 256, Window: 8}
	if err := h.validate(); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(c).Encode(h); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-events:
		if ev.hello != h {
			t.Fatalf("%+v", ev)
		}
		ev.reply <- h
	case <-time.After(time.Second):
		t.Fatal("no setup event")
	}
	var response falconHello
	if err := json.NewDecoder(c).Decode(&response); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	select {
	case ev := <-events:
		if ev.reply != nil {
			t.Fatal("expected teardown")
		}
	case <-time.After(time.Second):
		t.Fatal("no teardown event")
	}
	for _, bad := range []falconHello{{}, {Protocol: falconCMVersion, CID: 0x1000000, Encap: "udp4", Payload: 256, Window: 8}, {Protocol: falconCMVersion, Encap: "udp4", Payload: 256, Window: 65}} {
		if bad.validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	ids := falconCIDAllocator{next: 0xffffff}
	if cid, err := ids.allocate(); err != nil || cid != 0xffffff {
		t.Fatal(cid, err)
	}
	if _, err := ids.allocate(); err == nil {
		t.Fatal("CID wrapped")
	}
}

func TestFalconCMIPv6(t *testing.T) {
	n := &falconTestNetwork{sockets: make(map[netip.Addr]*falconTestSocket)}
	receiver := newFalconTestEngine(t, n, "::1", "--encap", "udp6")
	receiver.cfg.FalconCMPort = falconTestPort(t, "::1")
	startFalconTestReceiver(t, receiver)
	sender := newFalconTestEngine(t, n, "::1", "--encap", "udp6")
	sender.cfg.FalconCMPort = receiver.cfg.FalconCMPort
	c, err := sender.dialFalcon(context.Background(), netip.MustParseAddr("::1"), 99)
	if err != nil {
		t.Fatal(err)
	}
	defer c.cm.Close()
	if c.remoteCID != 7 || c.localCID != 99 {
		t.Fatalf("%+v", c)
	}
}
