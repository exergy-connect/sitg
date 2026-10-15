package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jbemmel/sitg/internal/config"
	"github.com/jbemmel/sitg/internal/link"
	"github.com/jbemmel/sitg/internal/pattern"
	"github.com/jbemmel/sitg/internal/wire"
)

type packetSocket interface {
	Send([]byte) error
	Recv([]byte) (int, error)
	SetNonblock(bool) error
}

// Engine runs a send or recv session.
type Engine struct {
	cfg    *config.Config
	sock   packetSocket
	ep     *link.Endpoint
	stats  *Stats
	paths  []netip.Addr
	dstMAC map[netip.Addr]net.HardwareAddr
	sel    *pattern.Selector
}

func New(cfg *config.Config, sock *link.Socket) (*Engine, error) {
	ep := sock.Endpoint()
	e := &Engine{
		cfg:    cfg,
		sock:   sock,
		ep:     ep,
		stats:  NewStats(string(cfg.Role)),
		dstMAC: make(map[netip.Addr]net.HardwareAddr),
		sel:    pattern.New(cfg),
	}
	if cfg.Role == config.RoleSend && cfg.Entropy == config.EntropySRv6 {
		paths, err := wire.AllPaths(wire.PathParams{
			Locator:  cfg.Locator,
			Paths:    cfg.Paths,
			Hops:     cfg.Hops,
			Radix:    cfg.Radix,
			USIDBase: cfg.USIDBase,
		})
		if err != nil {
			return nil, err
		}
		e.paths = paths
	}
	return e, nil
}

func (e *Engine) Run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if e.cfg.Role == config.RoleSend {
		return e.runSend(ctx)
	}
	return e.runRecv(ctx)
}

func (e *Engine) resolveMAC(ip netip.Addr) (net.HardwareAddr, error) {
	if mac, ok := e.dstMAC[ip]; ok {
		return mac, nil
	}
	if e.cfg.DstMAC != nil {
		e.dstMAC[ip] = e.cfg.DstMAC
		return e.cfg.DstMAC, nil
	}
	mac, err := link.ResolveDestinationMAC(e.ep, ip, e.cfg.ConnectTimeout)
	if err != nil {
		return nil, fmt.Errorf("resolve next-hop MAC for %s: %w", ip, err)
	}
	e.dstMAC[ip] = mac
	return mac, nil
}

// Resolve peers before the traffic clock starts, including every SRv6 path.
func (e *Engine) prepareMACs() error {
	destinations := e.sel.Peers()
	if len(e.paths) > 0 {
		destinations = e.paths
	}
	for _, dst := range destinations {
		if _, err := e.resolveMAC(dst); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) srcIP() (netip.Addr, error) {
	if e.cfg.IsIPv4() {
		if !e.ep.SrcIPv4.IsValid() {
			return netip.Addr{}, fmt.Errorf("interface %s has no IPv4 address", e.cfg.Iface)
		}
		return e.ep.SrcIPv4, nil
	}
	if !e.ep.SrcIPv6.IsValid() {
		return netip.Addr{}, fmt.Errorf("interface %s has no IPv6 address", e.cfg.Iface)
	}
	return e.ep.SrcIPv6, nil
}

func (e *Engine) buildOpts(dst netip.Addr, entropy uint16, pathIdx int) (wire.BuildOpts, error) {
	src, err := e.srcIP()
	if err != nil {
		return wire.BuildOpts{}, err
	}
	linkDst := dst
	if e.cfg.Entropy == config.EntropySRv6 && len(e.paths) > 0 {
		linkDst = e.paths[pathIdx%len(e.paths)]
	}
	mac, err := e.resolveMAC(linkDst)
	if err != nil {
		return wire.BuildOpts{}, err
	}
	opts := wire.BuildOpts{
		SrcMAC:   e.ep.SrcMAC,
		DstMAC:   mac,
		SrcIP:    src,
		DstIP:    dst,
		Encap:    string(e.cfg.Encap),
		IPProto:  e.cfg.IPProto,
		Entropy:  entropy,
		HopLimit: 64,
	}
	if e.cfg.Entropy == config.EntropySRv6 && len(e.paths) > 0 {
		opts.UseSRv6 = true
		opts.SRv6Dst = e.paths[pathIdx%len(e.paths)]
		if e.ep.SrcIPv6.IsValid() {
			opts.SRv6SrcIP = e.ep.SrcIPv6
		} else if src.Is6() {
			opts.SRv6SrcIP = src
		} else {
			return wire.BuildOpts{}, fmt.Errorf("SRv6 requires an IPv6 address on %s", e.cfg.Iface)
		}
	}
	return opts, nil
}

func (e *Engine) encodeData(psn, msgID, offset, length uint32, rtx bool, payload []byte) []byte {
	if e.cfg.Proto == config.ProtoMRC {
		return wire.EncodeMRCData(psn, e.cfg.QP, msgID, offset, length, rtx, payload)
	}
	return wire.EncodeUETData(psn, e.cfg.QP, msgID, offset, length, rtx, payload)
}

func (e *Engine) encodeSACK(cumAck uint32, bitmap uint64) []byte {
	if e.cfg.Proto == config.ProtoMRC {
		return wire.EncodeMRCSACK(e.cfg.QP, cumAck, bitmap)
	}
	return wire.EncodeUETSACK(e.cfg.QP, cumAck, bitmap)
}

func (e *Engine) buildFrame(opts wire.BuildOpts, transport []byte) ([]byte, error) {
	if e.cfg.Proto == config.ProtoMRC {
		return wire.BuildMRCFrame(opts, transport)
	}
	return wire.BuildUETFrame(opts, transport)
}

func (e *Engine) runSend(ctx context.Context) error {
	if e.cfg.Proto == config.ProtoFalcon {
		return e.runFalconSend(ctx)
	}
	if err := e.prepareMACs(); err != nil {
		return err
	}
	win := NewSendWindow(e.cfg.Window, e.cfg.RTO)
	deadline := time.Now().Add(e.cfg.Duration)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	rtoTicker := time.NewTicker(e.cfg.RTO / 2)
	if e.cfg.RTO/2 < time.Microsecond {
		rtoTicker.Reset(time.Millisecond)
	}
	defer rtoTicker.Stop()

	recvBuf := make([]byte, 65536)
	_ = e.sock.SetNonblock(true)

	pathIdx := 0
	entropyBase := uint16(10000)
	msgID := uint32(1)
	payloadScratch := make([]byte, e.cfg.PktSize)
	for i := range payloadScratch {
		payloadScratch[i] = byte(i)
	}

	tokens := float64(e.cfg.RateBps)
	lastRefill := time.Now()
	draining := false

	var (
		curDst     netip.Addr
		curMsgSize int
		curOffset  int
		haveMsg    bool
	)

	progress := func() {
		fmt.Fprintln(os.Stderr, e.stats.ProgressLine())
	}

	for {
		retransmitDue := false
		select {
		case <-ctx.Done():
			e.stats.MarkEnd()
			fmt.Fprint(os.Stderr, e.stats.FinalReport())
			return nil
		case <-ticker.C:
			progress()
		case <-rtoTicker.C:
			retransmitDue = true
		default:
		}

		// Apply queued SACKs before checking retransmission deadlines. A timer
		// waking this loop may be older than ACKs already waiting in the socket.
		for {
			n, err := e.sock.Recv(recvBuf)
			if err != nil {
				if isTimeout(err) || isWouldBlock(err) {
					break
				}
				return err
			}
			f, err := wire.ParseEthernetFrame(recvBuf[:n], e.cfg.IPProto)
			if err != nil || f.Type != wire.TypeSACK || f.QP != e.cfg.QP || f.Proto != string(e.cfg.Proto) {
				continue
			}
			e.stats.MarkStart()
			e.stats.SACKsRecv.Add(1)
			acked, _, rtt := win.ApplySACK(f.CumAck, f.Bitmap, time.Now())
			e.stats.BytesAcked.Add(acked)
			if rtt > 0 && rtt < time.Second {
				e.stats.ObserveRTT(rtt)
			}
		}

		if retransmitDue {
			if pkt := win.OldestExpired(time.Now()); pkt != nil {
				if err := e.retransmit(pkt, &pathIdx, entropyBase, win); err != nil {
					return err
				}
			}
		}

		now := time.Now()
		elapsed := now.Sub(lastRefill).Seconds()
		if elapsed > 0 {
			tokens += elapsed * float64(e.cfg.RateBps)
			maxBurst := float64(e.cfg.RateBps) * 0.01
			if tokens > maxBurst {
				tokens = maxBurst
			}
			lastRefill = now
		}

		if !draining && now.After(deadline) {
			draining = true
		}
		if draining {
			if win.Empty() {
				e.stats.MarkEnd()
				progress()
				fmt.Fprint(os.Stderr, e.stats.FinalReport())
				return nil
			}
			time.Sleep(100 * time.Microsecond)
			continue
		}

		if !haveMsg {
			curDst, curMsgSize = e.sel.Next()
			curOffset = 0
			haveMsg = true
		}

		if !win.CanSend() || tokens < float64(e.cfg.PktSize*8) {
			time.Sleep(10 * time.Microsecond)
			continue
		}

		for curOffset < curMsgSize {
			if !win.CanSend() || tokens < float64(e.cfg.PktSize*8) {
				break
			}
			if time.Now().After(deadline) {
				draining = true
				break
			}
			chunk := e.cfg.PktSize
			if curOffset+chunk > curMsgSize {
				chunk = curMsgSize - curOffset
			}
			psn := win.NextPSN()
			payload := payloadScratch[:chunk]
			transport := e.encodeData(psn, msgID, uint32(curOffset), uint32(curMsgSize), false, payload)
			entropy := entropyBase + uint16(pathIdx%e.cfg.Paths)
			opts, err := e.buildOpts(curDst, entropy, pathIdx)
			if err != nil {
				return err
			}
			frame, err := e.buildFrame(opts, transport)
			if err != nil {
				return err
			}
			e.stats.MarkStart()
			if err := e.sock.Send(frame); err != nil {
				return err
			}
			win.Track(&Inflight{
				PSN:       psn,
				Payload:   append([]byte(nil), payload...),
				MsgID:     msgID,
				Offset:    uint32(curOffset),
				Length:    uint32(curMsgSize),
				SentAt:    time.Now(),
				Bytes:     chunk,
				PathIndex: pathIdx,
				DstIP:     curDst.String(),
			})
			e.stats.PacketsSent.Add(1)
			e.stats.BytesSent.Add(uint64(chunk))
			tokens -= float64(len(frame) * 8)
			pathIdx++
			curOffset += chunk
		}
		if curOffset >= curMsgSize {
			haveMsg = false
			msgID++
		}
	}
}

func (e *Engine) retransmit(pkt *Inflight, pathIdx *int, entropyBase uint16, win *SendWindow) error {
	*pathIdx++
	dst := e.cfg.Dst
	if pkt.DstIP != "" {
		if addr, err := netip.ParseAddr(pkt.DstIP); err == nil {
			dst = addr
		}
	}
	if !dst.IsValid() {
		peers := e.sel.Peers()
		if len(peers) == 0 {
			return fmt.Errorf("retransmit: no destination")
		}
		dst = peers[0]
	}
	entropy := entropyBase + uint16(*pathIdx%e.cfg.Paths)
	opts, err := e.buildOpts(dst, entropy, *pathIdx)
	if err != nil {
		return err
	}
	transport := e.encodeData(pkt.PSN, pkt.MsgID, pkt.Offset, pkt.Length, true, pkt.Payload)
	frame, err := e.buildFrame(opts, transport)
	if err != nil {
		return err
	}
	if err := e.sock.Send(frame); err != nil {
		return err
	}
	win.MarkRetransmit(pkt.PSN, time.Now())
	e.stats.PacketsSent.Add(1)
	e.stats.Retransmits.Add(1)
	e.stats.BytesSent.Add(uint64(pkt.Bytes))
	return nil
}

func (e *Engine) runRecv(ctx context.Context) error {
	return e.runReceiver(ctx)
}

func isWouldBlock(err error) bool {
	if err == nil {
		return false
	}
	if errno, ok := err.(syscall.Errno); ok {
		return errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK
	}
	return false
}

func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}
