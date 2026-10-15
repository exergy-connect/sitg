package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/jbemmel/sitg/internal/wire"
)

type falconConnection struct {
	peer                netip.Addr
	localIP             netip.Addr
	encap               string
	localCID, remoteCID uint32
	payload             int
	receiveWindow       int
	nextRSN             uint32
	window              *SendWindow
	tracker             *RecvTracker
	cm                  net.Conn
	closed              chan struct{}
	last                *wire.Frame
	pending             int
}

func (e *Engine) finishStats() {
	e.stats.MarkEnd()
	fmt.Fprintf(os.Stderr, "iface=%s %s\n%s", e.cfg.Iface, e.stats.ProgressLine(), e.stats.FinalReport())
}

func (e *Engine) runFalconSend(ctx context.Context) error {
	if err := e.sock.SetNonblock(true); err != nil {
		return err
	}
	conns := make(map[netip.Addr]*falconConnection)
	byCID := make(map[uint32]*falconConnection)
	defer func() {
		for _, c := range conns {
			_ = c.cm.Close()
		}
	}()
	ids := falconCIDAllocator{next: e.cfg.QP}
	// Complete all setup before starting the traffic duration and rate accounting.
	for _, peer := range e.sel.Peers() {
		if conns[peer] != nil {
			continue
		}
		if len(conns) >= maxFalconConnections {
			return fmt.Errorf("too many Falcon peers")
		}
		cid, err := ids.allocate()
		if err != nil {
			return err
		}
		c, err := e.dialFalcon(ctx, peer, cid)
		if err != nil {
			return err
		}
		conns[peer], byCID[cid] = c, c
		fmt.Fprintf(os.Stderr, "Falcon connected peer=%s local-cid=%d remote-cid=%d payload=%d window=%d\n", peer, c.localCID, c.remoteCID, c.payload, c.window.capacity)
	}
	if len(conns) == 0 {
		return fmt.Errorf("Falcon has no peers")
	}
	if err := e.prepareMACs(); err != nil {
		return err
	}
	defer e.finishStats()
	deadline := time.Now().Add(e.cfg.Duration)
	progress := time.NewTicker(time.Second)
	defer progress.Stop()
	buf := make([]byte, 65536)
	scratch := make([]byte, e.cfg.PktSize)
	for i := range scratch {
		scratch[i] = byte(i)
	}
	path := 0
	tokens := e.rateTokens() * 0.01
	lastRefill := time.Now()
	var drainDeadline time.Time
	var current *falconConnection
	var msgSize, offset int

	send := func(c *falconConnection, pkt *Inflight, rtx bool) error {
		opts, err := e.buildOpts(c.peer, 10000+uint16(path%e.cfg.Paths), path)
		if err != nil {
			return err
		}
		frame, err := wire.BuildFalconFrame(opts, wire.EncodeFalconData(pkt.PSN, c.remoteCID, pkt.MsgID, pkt.Payload))
		if err != nil {
			return err
		}
		if err := e.sock.Send(frame); err != nil {
			return err
		}
		e.stats.MarkStart()
		e.stats.PacketsSent.Add(1)
		e.stats.BytesSent.Add(uint64(pkt.Bytes))
		if rtx {
			c.window.MarkRetransmit(pkt.PSN, time.Now())
			e.stats.Retransmits.Add(1)
		} else {
			pkt.SentAt = time.Now()
			c.window.Track(pkt)
		}
		tokens -= e.packetCost(len(frame))
		path++
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-progress.C:
			fmt.Fprintln(os.Stderr, e.stats.ProgressLine())
		default:
		}
		// Bound each receive batch so heavy/duplicate traffic cannot starve timers.
		for i := 0; i < 64; i++ {
			n, err := e.sock.Recv(buf)
			if err != nil {
				if isTimeout(err) || isWouldBlock(err) {
					break
				}
				return err
			}
			f, err := wire.ParseEthernetFrame(buf[:n], e.cfg.IPProto)
			if err != nil || f.Proto != "falcon" || f.Type != wire.TypeSACK || f.Encap != string(e.cfg.Encap) {
				continue
			}
			c := byCID[f.QP]
			src, _ := e.srcIP()
			if c == nil || f.SrcIP != c.peer || f.DstIP != src || f.CumAck > c.window.nextPSN {
				continue
			}
			acked, _, rtt := c.window.ApplySACK(f.CumAck, f.Bitmap, time.Now())
			e.stats.SACKsRecv.Add(1)
			e.stats.BytesAcked.Add(acked)
			if rtt > 0 {
				e.stats.ObserveRTT(rtt)
			}
		}
		now := time.Now()
		tokens = min(tokens+now.Sub(lastRefill).Seconds()*e.rateTokens(), max(e.rateTokens()*0.01, e.packetCost(e.cfg.PktSize+256)))
		lastRefill = now
		if !now.Before(deadline) && drainDeadline.IsZero() {
			drainDeadline = now.Add(e.cfg.ConnectTimeout)
		}
		empty := true
		for _, c := range conns {
			select {
			case <-c.closed:
				return fmt.Errorf("Falcon connection to %s closed", c.peer)
			default:
			}
			if !c.window.Empty() {
				empty = false
			}
			if pkt := c.window.OldestExpired(now); pkt != nil && tokens >= e.packetCost(pkt.Bytes) {
				if err := send(c, pkt, true); err != nil {
					return err
				}
			}
		}
		if !drainDeadline.IsZero() {
			if empty {
				return nil
			}
			if now.After(drainDeadline) {
				return fmt.Errorf("Falcon drain timed out with unacknowledged packets")
			}
			time.Sleep(50 * time.Microsecond)
			continue
		}
		if current == nil {
			peer, size := e.sel.Next()
			current = conns[peer]
			msgSize = size
			offset = 0
		}
		chunk := min(current.payload, msgSize-offset)
		if !current.window.CanSend() || tokens < e.packetCost(chunk) {
			time.Sleep(10 * time.Microsecond)
			continue
		}
		// The shared reliability window uses ordinary uint32 comparisons. Fail before
		// rollover rather than silently treating a new packet as an old duplicate.
		if current.window.nextPSN == ^uint32(0) {
			return fmt.Errorf("Falcon PSN space exhausted; establish a new connection")
		}
		pkt := &Inflight{PSN: current.window.NextPSN(), MsgID: current.nextRSN, Payload: append([]byte(nil), scratch[:chunk]...), Bytes: chunk}
		if err := send(current, pkt, false); err != nil {
			return err
		}
		offset += chunk
		if offset == msgSize {
			current.nextRSN++
			current = nil
		}
	}
}
