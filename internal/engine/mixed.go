package engine

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/jbemmel/sitg/internal/config"
	"github.com/jbemmel/sitg/internal/wire"
)

var mixedProtocols = [...]config.Proto{config.ProtoUET, config.ProtoFalcon, config.ProtoMRC}

type mixedFlowKey struct {
	proto config.Proto
	peer  netip.Addr
}

type mixedFlow struct {
	proto  config.Proto
	peer   netip.Addr
	window *SendWindow
	falcon *falconConnection
	msgID  uint32
}

type mixedMessage struct {
	flow         *mixedFlow
	size, offset int
}

type mixedPhase struct {
	index          int
	start          time.Time
	packets, bytes uint64
}

func (p *mixedPhase) advance(limit config.SwitchLimit, now time.Time) bool {
	if (limit.Interval > 0 && now.Sub(p.start) >= limit.Interval) ||
		(limit.Packets > 0 && p.packets >= limit.Packets) ||
		(limit.Bytes > 0 && p.bytes >= limit.Bytes) {
		p.index = (p.index + 1) % len(mixedProtocols)
		p.start, p.packets, p.bytes = now, 0, 0
		return true
	}
	return false
}

// One socket reader demultiplexes all ACKs. Only new data follows the active
// phase; reliability work continues for inactive protocols as well.
func (e *Engine) runMixedSend(ctx context.Context) error {
	if err := e.sock.SetNonblock(true); err != nil {
		return err
	}
	flows := make(map[mixedFlowKey]*mixedFlow)
	byCID := make(map[uint32]*mixedFlow)
	defer func() {
		for _, f := range byCID {
			_ = f.falcon.cm.Close()
		}
	}()
	ids := falconCIDAllocator{next: e.cfg.QP}
	for _, peer := range e.sel.Peers() {
		if flows[mixedFlowKey{config.ProtoFalcon, peer}] != nil {
			continue
		}
		if len(byCID) >= maxFalconConnections {
			return fmt.Errorf("too many mixed Falcon peers")
		}
		cid, err := ids.allocate()
		if err != nil {
			return err
		}
		c, err := e.dialFalcon(ctx, peer, cid)
		if err != nil {
			return err
		}
		f := &mixedFlow{proto: config.ProtoFalcon, peer: peer, window: c.window, falcon: c, msgID: 1}
		flows[mixedFlowKey{config.ProtoFalcon, peer}], byCID[cid] = f, f
		for _, proto := range []config.Proto{config.ProtoUET, config.ProtoMRC} {
			flows[mixedFlowKey{proto, peer}] = &mixedFlow{proto: proto, peer: peer, window: NewSendWindow(e.cfg.Window, e.cfg.RTO), msgID: 1}
		}
		fmt.Fprintf(os.Stderr, "Falcon connected peer=%s local-cid=%d remote-cid=%d payload=%d window=%d\n", peer, cid, c.remoteCID, c.payload, c.window.capacity)
	}
	if len(flows) == 0 {
		return fmt.Errorf("mixed sender has no peers")
	}
	if err := e.prepareMACs(); err != nil {
		return err
	}
	var totals [3]struct{ packets, bytes, retries uint64 }
	defer func() {
		e.finishStats()
		for i, proto := range mixedProtocols {
			fmt.Fprintf(os.Stderr, "mixed %s: original packets=%d payload bytes=%d retransmissions=%d\n", proto, totals[i].packets, totals[i].bytes, totals[i].retries)
		}
	}()
	start := time.Now()
	deadline := start.Add(e.cfg.Duration)
	phase := mixedPhase{start: start}
	var messages [3]mixedMessage
	progress := time.NewTicker(time.Second)
	defer progress.Stop()
	buf := make([]byte, 65536)
	scratch := make([]byte, e.cfg.PktSize)
	for i := range scratch {
		scratch[i] = byte(i)
	}
	path := 0
	maxBurst := max(e.rateTokens()*0.01, e.packetCost(e.cfg.PktSize+256))
	tokens, lastRefill := maxBurst, start
	var drainDeadline time.Time
	send := func(f *mixedFlow, pkt *Inflight, retry bool) error {
		opts, err := e.buildOpts(f.peer, 10000+uint16(path%e.cfg.Paths), path)
		if err != nil {
			return err
		}
		var raw []byte
		switch f.proto {
		case config.ProtoUET:
			raw, err = wire.BuildUETFrame(opts, wire.EncodeUETData(pkt.PSN, e.cfg.QP, pkt.MsgID, pkt.Offset, pkt.Length, retry, pkt.Payload, f.window.ClearPSN()))
		case config.ProtoMRC:
			raw, err = wire.BuildMRCFrame(opts, wire.EncodeMRCData(pkt.PSN, e.cfg.QP, pkt.MsgID, pkt.Offset, pkt.Length, retry, pkt.Payload))
		case config.ProtoFalcon:
			raw, err = wire.BuildFalconFrame(opts, wire.EncodeFalconData(pkt.PSN, f.falcon.remoteCID, pkt.MsgID, pkt.Payload))
		}
		if err != nil {
			return err
		}
		if err := e.sock.Send(raw); err != nil {
			return err
		}
		if f.proto == config.ProtoMRC {
			e.noteMRCData(opts, e.cfg.QP, pkt.PSN, time.Now())
		}
		e.stats.MarkStart()
		e.stats.PacketsSent.Add(1)
		e.stats.BytesSent.Add(uint64(pkt.Bytes))
		index := 0
		for mixedProtocols[index] != f.proto {
			index++
		}
		if retry {
			f.window.MarkRetransmit(pkt.PSN, time.Now())
			e.stats.Retransmits.Add(1)
			totals[index].retries++
		} else {
			pkt.SentAt = time.Now()
			f.window.Track(pkt)
			totals[index].packets++
			totals[index].bytes += uint64(pkt.Bytes)
		}
		tokens -= e.packetCost(len(raw))
		path++
		return nil
	}
	src, err := e.srcIP()
	if err != nil {
		return err
	}
	for {
		if err := e.serviceMRC(time.Now()); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-progress.C:
			fmt.Fprintf(os.Stderr, "mixed active=%s %s\n", mixedProtocols[phase.index], e.stats.ProgressLine())
		default:
		}
		// Bound receive work so unrelated interface traffic cannot starve switches.
		for i := 0; i < 256; i++ {
			n, err := e.sock.Recv(buf)
			if err != nil {
				if isWouldBlock(err) || isTimeout(err) {
					break
				}
				return err
			}
			ack, err := wire.ParseEthernetFrame(buf[:n], e.cfg.IPProto)
			if err == nil {
				handled, controlErr := e.handleMRC(ack, time.Now())
				if controlErr != nil {
					return controlErr
				}
				if handled {
					continue
				}
			}
			if err != nil || ack.Type != wire.TypeSACK || ack.DstIP != src || ack.Encap != string(e.cfg.Encap) {
				continue
			}
			f := flows[mixedFlowKey{config.Proto(ack.Proto), ack.SrcIP}]
			if ack.Proto == "falcon" {
				f = byCID[ack.QP]
				if f == nil || f.peer != ack.SrcIP {
					continue
				}
			} else if ack.QP != e.cfg.QP {
				continue
			}
			if f == nil || ack.CumAck > f.window.nextPSN {
				continue
			}
			if ack.Proto == "mrc" {
				e.noteMRCSACK(ack, time.Now())
			}
			acked, _, rtt := f.window.ApplySACK(ack.CumAck, ack.Bitmap, time.Now())
			e.stats.SACKsRecv.Add(1)
			e.stats.BytesAcked.Add(acked)
			if rtt > 0 {
				e.stats.ObserveRTT(rtt)
			}
		}
		now := time.Now()
		tokens = min(tokens+now.Sub(lastRefill).Seconds()*e.rateTokens(), maxBurst)
		lastRefill = now
		if !now.Before(deadline) && drainDeadline.IsZero() {
			drainDeadline = now.Add(e.cfg.ConnectTimeout)
		}
		empty := true
		for _, f := range flows {
			if f.falcon != nil {
				select {
				case <-f.falcon.closed:
					return fmt.Errorf("mixed Falcon connection to %s closed", f.peer)
				default:
				}
			}
			if !f.window.Empty() {
				empty = false
			}
			if pkt := f.window.OldestExpired(now); pkt != nil && tokens >= e.packetCost(pkt.Bytes) {
				if err := send(f, pkt, true); err != nil {
					return err
				}
			}
		}
		if !drainDeadline.IsZero() {
			if empty {
				return nil
			}
			if !now.Before(drainDeadline) {
				return fmt.Errorf("mixed drain timed out with unacknowledged packets")
			}
			time.Sleep(50 * time.Microsecond)
			continue
		}
		phase.advance(e.cfg.SwitchEvery, now)
		message := &messages[phase.index]
		if message.flow == nil {
			peer, size := e.sel.Next()
			message.flow, message.size, message.offset = flows[mixedFlowKey{mixedProtocols[phase.index], peer}], size, 0
		}
		f := message.flow
		payload := e.cfg.PktSize
		if f.falcon != nil {
			payload = f.falcon.payload
		}
		chunk := min(payload, message.size-message.offset)
		if limit := e.cfg.SwitchEvery.Bytes; limit > 0 && uint64(chunk) > limit-phase.bytes {
			chunk = int(limit - phase.bytes)
		}
		if !f.window.CanSend() || tokens < e.packetCost(chunk) {
			time.Sleep(10 * time.Microsecond)
			continue
		}
		if f.window.nextPSN == ^uint32(0) || (f.proto == config.ProtoMRC && f.window.nextPSN >= 1<<24) {
			return fmt.Errorf("mixed %s PSN space exhausted", f.proto)
		}
		pkt := &Inflight{PSN: f.window.NextPSN(), MsgID: f.msgID, Offset: uint32(message.offset), Length: uint32(message.size), Payload: append([]byte(nil), scratch[:chunk]...), Bytes: chunk}
		if err := send(f, pkt, false); err != nil {
			return err
		}
		phase.packets++
		phase.bytes += uint64(chunk)
		message.offset += chunk
		if message.offset == message.size {
			f.msgID++
			message.flow = nil
		}
	}
}
