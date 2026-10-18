package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/jbemmel/sitg/internal/config"
	"github.com/jbemmel/sitg/internal/wire"
)

const maxReceiverFlows = 4096

// Entropy changes paths within a flow; protocol, encapsulation, endpoints and
// QP identify independent reliability windows. Native and SRv6 runs stay separate.
type receiverFlowKey struct {
	proto, encap string
	src, dst     netip.Addr
	qp           uint32
	srv6         bool
}

func (e *Engine) acceptsEncap(encap string) bool {
	return e.cfg.Encap == config.EncapAll || string(e.cfg.Encap) == encap
}

func (e *Engine) receiverIPs() []netip.Addr {
	var ips []netip.Addr
	if (e.cfg.Encap == config.EncapAll || e.cfg.IsIPv4()) && e.ep.SrcIPv4.IsValid() {
		ips = append(ips, e.ep.SrcIPv4)
	}
	if (e.cfg.Encap == config.EncapAll || !e.cfg.IsIPv4()) && e.ep.SrcIPv6.IsValid() {
		ips = append(ips, e.ep.SrcIPv6)
	}
	return ips
}

func (e *Engine) receiverACK(c *falconConnection) error {
	if c.last == nil {
		return nil
	}
	cum, bm, _ := c.tracker.Snapshot()
	opts := wire.BuildOpts{SrcMAC: e.ep.SrcMAC, DstMAC: c.last.SrcMAC, SrcIP: c.localIP, DstIP: c.peer, Encap: c.encap, IPProto: e.cfg.IPProto, Entropy: c.last.Entropy}
	if len(e.paths) > 0 {
		path, routingEV := e.ackPath, c.last.Entropy
		if c.last.Proto == "mrc" && e.mrcReverseEnabled() {
			peer := e.reversePeer(mrcReverseKey{c.localIP, c.peer, c.encap, c.remoteCID})
			selected, ok := e.confirmedPath(peer, time.Now())
			if !ok {
				return nil
			}
			path, routingEV = selected, uint16(10000+selected)
		}
		var err error
		opts, err = e.buildOpts(c.peer, routingEV, path)
		if err != nil {
			return err
		}
		// Generic receivers accept multiple inner encapsulations. Preserve
		// this flow's addresses/encapsulation inside the routed ACK wrapper.
		opts.SrcIP = c.localIP
		opts.Encap = c.encap
		e.ackPath = (e.ackPath + 1) % len(e.paths)
	}
	var raw []byte
	var err error
	switch c.last.Proto {
	case "uet":
		raw, err = wire.BuildUETFrame(opts, wire.EncodeUETSACK(c.remoteCID, cum, bm))
	case "mrc":
		raw, err = wire.BuildMRCFrame(opts, wire.EncodeMRCSACKForPacket(c.remoteCID, cum, bm, c.last.MRCEV, c.last.PSN))
	case "falcon":
		raw, err = wire.BuildFalconFrame(opts, wire.EncodeFalconSACK(c.remoteCID, cum, bm))
	default:
		return wire.ErrUnknownProto
	}
	if err != nil {
		return err
	}
	if err := e.sock.Send(raw); err != nil {
		return err
	}
	c.pending = 0
	e.stats.SACKsSent.Add(1)
	return nil
}

// One raw socket reader demultiplexes all selected protocols. Falcon CM events
// and data share this loop, keeping setup, teardown and reliability state ordered.
func (e *Engine) runReceiver(ctx context.Context) error {
	if err := e.sock.SetNonblock(true); err != nil {
		return err
	}
	ips := e.receiverIPs()
	if len(ips) == 0 {
		return fmt.Errorf("interface %s has no address for %s", e.cfg.Iface, e.cfg.Encap)
	}
	local := make(map[netip.Addr]bool)
	for _, ip := range ips {
		local[ip] = true
	}
	cmCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	events := make(chan falconCMEvent)
	var listeners []net.Listener
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	{
		// Separate v4/v6 listeners prevent a wildcard socket from claiming addresses
		// outside the selected interface or masking an address-family bind failure.
		for _, ip := range ips {
			network := "tcp6"
			if ip.Is4() {
				network = "tcp4"
			}
			lc := net.ListenConfig{}
			listener, err := lc.Listen(cmCtx, network, net.JoinHostPort(ip.String(), strconv.Itoa(e.cfg.FalconCMPort)))
			if err != nil {
				return fmt.Errorf("SITG control listen on %s: %w", ip, err)
			}
			listeners = append(listeners, listener)
		}
		// Start only after all binds succeed, so partial startup leaves no CM peers.
		for _, l := range listeners {
			go serveFalconCM(cmCtx, l, e.cfg.ConnectTimeout, events)
			fmt.Fprintf(os.Stderr, "SITG control listening on %s\n", l.Addr())
		}
	}
	flows := make(map[receiverFlowKey]*falconConnection)
	conns := make(map[uint32]*falconConnection)
	byTCP := make(map[net.Conn]*falconConnection)
	defer func() {
		for _, c := range conns {
			_ = c.cm.Close()
		}
	}()
	ids := falconCIDAllocator{next: e.cfg.QP}
	updateGaps := func() {
		var gaps uint64
		for _, c := range flows {
			_, _, g := c.tracker.Snapshot()
			gaps += uint64(g)
		}
		for _, c := range e.mrcInbound {
			_, _, g := c.tracker.Snapshot()
			gaps += uint64(g)
		}
		for _, c := range conns {
			_, _, g := c.tracker.Snapshot()
			gaps += uint64(g)
		}
		e.stats.GapsOpen.Store(gaps)
	}
	flush := func() error {
		if err := e.serviceMRC(time.Now()); err != nil {
			return err
		}
		for _, c := range flows {
			if c.pending > 0 {
				if err := e.receiverACK(c); err != nil {
					return err
				}
			}
		}
		for _, c := range conns {
			if c.pending > 0 {
				if err := e.receiverACK(c); err != nil {
					return err
				}
			}
		}
		return nil
	}
	defer func() { updateGaps(); e.finishStats() }()
	finish := func() error { return flush() }
	progress := time.NewTicker(time.Second)
	defer progress.Stop()
	ackTimer := time.NewTicker(500 * time.Microsecond)
	defer ackTimer.Stop()
	var deadline <-chan time.Time
	if e.cfg.Duration > 0 {
		timer := time.NewTimer(e.cfg.Duration)
		defer timer.Stop()
		deadline = timer.C
	}
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return finish()
		case <-deadline:
			return finish()
		case ev := <-events:
			if ev.reply == nil {
				if c := byTCP[ev.conn]; c != nil {
					delete(conns, c.localCID)
					delete(byTCP, ev.conn)
					updateGaps()
				}
				continue
			}
			if ev.hello.Protocol == "sitg-flow-reset/1" {
				response := ev.hello
				h := ev.hello
				protoOK := h.ResetProto == "uet" || h.ResetProto == "mrc"
				encapOK := h.Encap == "udp4" || h.Encap == "udp6" || h.Encap == "ip4" || h.Encap == "ip6"
				familyOK := (h.Encap == "udp4" || h.Encap == "ip4") == ev.local.Is4()
				if !protoOK || !encapOK || !local[ev.local] || !familyOK || !e.acceptsEncap(h.Encap) ||
					(e.cfg.Proto != config.ProtoAll && string(e.cfg.Proto) != h.ResetProto) ||
					(!e.cfg.AcceptAnyQP && h.Service != e.cfg.QP) {
					response.Error = "reset does not match receiver protocol, encapsulation or QP"
				} else {
					for key := range flows {
						if key.proto == h.ResetProto && key.encap == h.Encap && key.src == ev.peer && key.dst == ev.local && key.qp == h.Service {
							delete(flows, key)
						}
					}
					for key := range e.mrcInbound {
						if key.proto == h.ResetProto && key.encap == h.Encap && key.src == ev.peer && key.dst == ev.local && key.qp == h.Service {
							delete(e.mrcInbound, key)
						}
					}
					reverseKey := mrcReverseKey{ev.local, ev.peer, h.Encap, h.Service}
					if owner := e.mrcReverse[reverseKey]; owner != nil {
						for key, probe := range e.mrcProbes {
							if probe.owner == owner {
								delete(e.mrcProbes, key)
							}
						}
						delete(e.mrcReverse, reverseKey)
					}
					updateGaps()
				}
				ev.reply <- response
				continue
			}
			response := e.falconHello(0)
			response.Encap = ev.hello.Encap
			if e.cfg.AcceptAnyQP {
				response.Service = ev.hello.Service
			}
			err := ev.hello.validate()
			if e.cfg.Proto != config.ProtoFalcon && e.cfg.Proto != config.ProtoAll {
				err = fmt.Errorf("receiver does not accept Falcon")
			}
			if err == nil {
				switch {
				case !e.cfg.AcceptAnyQP && ev.hello.Service != e.cfg.QP:
					err = fmt.Errorf("service mismatch: sender qp=%d, receiver qp=%d (set --qp to match)", ev.hello.Service, e.cfg.QP)
				case !e.acceptsEncap(ev.hello.Encap):
					err = fmt.Errorf("encapsulation mismatch: sender encap=%s, receiver encap=%s", ev.hello.Encap, e.cfg.Encap)
				case !local[ev.local]:
					err = fmt.Errorf("local address %s is not enabled on receiver interface %s", ev.local, e.cfg.Iface)
				case (ev.hello.Encap == "udp4") != ev.local.Is4():
					err = fmt.Errorf("encapsulation %s does not match local address %s", ev.hello.Encap, ev.local)
				}
			}
			if err == nil {
				for _, c := range conns {
					if c.peer == ev.peer && c.localIP == ev.local && c.remoteCID == ev.hello.CID {
						err = fmt.Errorf("peer receive CID already connected")
						break
					}
				}
			}
			if err == nil && len(conns) >= maxFalconConnections {
				err = fmt.Errorf("connection limit reached")
			}
			var cid uint32
			if err == nil {
				cid, err = ids.allocate()
			}
			if err != nil {
				response.Error = err.Error()
				ev.reply <- response
				continue
			}
			response.CID = cid
			response.Payload = min(response.Payload, ev.hello.Payload)
			response.Window = min(response.Window, ev.hello.Window)
			c := &falconConnection{peer: ev.peer, localIP: ev.local, encap: response.Encap, localCID: cid, remoteCID: ev.hello.CID, payload: response.Payload, receiveWindow: response.Window, tracker: NewRecvTracker(), cm: ev.conn}
			conns[cid], byTCP[ev.conn] = c, c
			ev.reply <- response
			fmt.Fprintf(os.Stderr, "Falcon accepted peer=%s local-cid=%d remote-cid=%d encap=%s\n", c.peer, c.localCID, c.remoteCID, c.encap)
			continue
		case <-progress.C:
			updateGaps()
			fmt.Fprintf(os.Stderr, "iface=%s %s\n", e.cfg.Iface, e.stats.ProgressLine())
		case <-ackTimer.C:
			if err := flush(); err != nil {
				return err
			}
		default:
		}
		n, err := e.sock.Recv(buf)
		if err != nil {
			if isTimeout(err) || isWouldBlock(err) {
				time.Sleep(10 * time.Microsecond)
				continue
			}
			return err
		}
		f, err := wire.ParseEthernetFrame(buf[:n], e.cfg.IPProto)
		if err == nil {
			handled, controlErr := e.handleMRC(f, time.Now())
			if controlErr != nil {
				return controlErr
			}
			if handled {
				continue
			}
		}
		if err != nil || f.Type != wire.TypeData || !local[f.DstIP] || !e.acceptsEncap(f.Encap) {
			continue
		}
		if e.cfg.Proto != config.ProtoAll && f.Proto != string(e.cfg.Proto) {
			continue
		}
		var c *falconConnection
		if f.Proto == "falcon" {
			c = conns[f.QP]
			if c == nil || c.peer != f.SrcIP || c.localIP != f.DstIP || c.encap != f.Encap || len(f.Payload) > c.payload {
				continue
			}
			cum, _, _ := c.tracker.Snapshot()
			if f.PSN >= cum && f.PSN-cum >= uint32(c.receiveWindow) {
				continue
			}
		} else {
			if !e.cfg.AcceptAnyQP && f.QP != e.cfg.QP {
				continue
			}
			key := receiverFlowKey{proto: f.Proto, encap: f.Encap, src: f.SrcIP, dst: f.DstIP, qp: f.QP, srv6: f.OuterSRv6}
			c = flows[key]
			if c == nil {
				if len(flows) >= maxReceiverFlows {
					continue
				}
				c = &falconConnection{peer: f.SrcIP, localIP: f.DstIP, encap: f.Encap, remoteCID: f.QP, tracker: NewRecvTracker()}
				flows[key] = c
			}
		}
		e.stats.MarkStart()
		e.stats.PacketsRecv.Add(1)
		if f.RTX {
			e.stats.RTXFlagged.Add(1)
		}
		duplicate, _, _ := c.tracker.Observe(f.PSN)
		if duplicate {
			e.stats.Duplicates.Add(1)
		} else {
			e.stats.BytesUnique.Add(uint64(len(f.Payload)))
		}
		c.last = f
		c.pending++
		if c.pending >= e.cfg.SackEvery {
			if err := e.receiverACK(c); err != nil {
				return err
			}
		}
	}
}
