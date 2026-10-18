package engine

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sort"
	"time"

	"github.com/jbemmel/sitg/internal/config"
	"github.com/jbemmel/sitg/internal/wire"
)

type mrcReverseKey struct {
	local, peer netip.Addr
	encap       string
	qp          uint32
}
type mrcProof struct {
	path int
	at   time.Time
}
type mrcSent struct {
	ev uint32
	at time.Time
}
type mrcReversePeer struct {
	key                                  mrcReverseKey
	rtt                                  time.Duration
	lastInbound, lastOutbound, lastProbe time.Time
	planes                               []int
	candidates                           map[int][]int
	good                                 map[int]mrcProof
	sent                                 map[uint32]mrcSent
	planeCursor, controlCursor           int
}
type mrcProbeKey struct {
	local, peer netip.Addr
	encap       string
	id          uint16
}
type mrcProbe struct {
	owner *mrcReversePeer
	path  int
	sent  time.Time
}

func (e *Engine) mrcReverseEnabled() bool {
	return len(e.paths) > 0 && (e.cfg.Proto == config.ProtoMRC || e.cfg.Proto == config.ProtoAll || e.cfg.Proto == config.ProtoMixed)
}
func (e *Engine) reversePeer(key mrcReverseKey) *mrcReversePeer {
	if e.mrcReverse == nil {
		e.mrcReverse = make(map[mrcReverseKey]*mrcReversePeer)
	}
	if p := e.mrcReverse[key]; p != nil {
		return p
	}
	if len(e.mrcReverse) >= maxReceiverFlows {
		return nil
	}
	rtt := e.cfg.ReverseRTT
	if rtt <= 0 {
		rtt = time.Millisecond
	}
	p := &mrcReversePeer{key: key, rtt: rtt, candidates: make(map[int][]int), good: make(map[int]mrcProof), sent: make(map[uint32]mrcSent)}
	for i := range e.paths {
		plane := e.pathPlane(i)
		p.candidates[plane] = append(p.candidates[plane], i)
	}
	for plane := range p.candidates {
		p.planes = append(p.planes, plane)
	}
	sort.Ints(p.planes)
	e.mrcReverse[key] = p
	return p
}
func (e *Engine) pathPlane(path int) int {
	if len(e.cfg.EVPlanes) > path {
		return e.cfg.EVPlanes[path]
	}
	return 0
}
func (e *Engine) proofTTL(p *mrcReversePeer) time.Duration {
	return max(8*p.rtt*time.Duration(len(p.planes)), e.cfg.RTO)
}
func (e *Engine) probeTimeout(p *mrcReversePeer) time.Duration { return max(4*p.rtt, e.cfg.RTO) }
func (p *mrcReversePeer) sampleRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}
	p.rtt = max(100*time.Microsecond, min(time.Second, (7*p.rtt+sample)/8))
}
func (e *Engine) confirmedPath(p *mrcReversePeer, now time.Time) (int, bool) {
	if p == nil || len(p.planes) == 0 {
		return 0, false
	}
	for i := 0; i < len(p.planes); i++ {
		plane := p.planes[p.controlCursor%len(p.planes)]
		p.controlCursor++
		proof, ok := p.good[plane]
		if ok && now.Sub(proof.at) <= e.proofTTL(p) {
			return proof.path, true
		}
		delete(p.good, plane)
	}
	return 0, false
}
func (e *Engine) mrcOpts(key mrcReverseKey, path int) (wire.BuildOpts, error) {
	opts, err := e.buildOpts(key.peer, uint16(10000+path), path)
	opts.SrcIP, opts.Encap = key.local, key.encap
	return opts, err
}

// Node-scope probes have no QP reliability semantics. Their pending records
// retain the originating QP, exact endpoints, candidate EV and send time.
func (e *Engine) sendEVProbe(p *mrcReversePeer, now time.Time) error {
	if len(p.planes) == 0 || len(e.mrcProbes) >= 65536 {
		return nil
	}
	plane := p.planes[p.planeCursor%len(p.planes)]
	p.planeCursor++
	candidates := p.candidates[plane]
	path := candidates[rand.IntN(len(candidates))]
	if e.mrcProbes == nil {
		e.mrcProbes = make(map[mrcProbeKey]mrcProbe)
	}
	// At most one outstanding probe per candidate/QP; lost probes expire.
	for _, pending := range e.mrcProbes {
		if pending.owner == p && pending.path == path {
			return nil
		}
	}
	var key mrcProbeKey
	found := false
	for i := 0; i < 65536; i++ {
		e.mrcProbeID++
		key = mrcProbeKey{p.key.local, p.key.peer, p.key.encap, e.mrcProbeID}
		if _, exists := e.mrcProbes[key]; !exists {
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	opts, err := e.mrcOpts(p.key, path)
	if err != nil {
		return err
	}
	raw, err := wire.BuildMRCFrame(opts, wire.EncodeMRCEVProbe(key.id, false))
	if err != nil {
		return err
	}
	if err = e.sock.Send(raw); err != nil {
		return err
	}
	e.mrcProbes[key] = mrcProbe{p, path, now}
	e.stats.EVProbesSent.Add(1)
	return nil
}

func (e *Engine) allPlanesConfirmed(p *mrcReversePeer, now time.Time) bool {
	for _, plane := range p.planes {
		proof, ok := p.good[plane]
		if !ok || now.Sub(proof.at) > e.proofTTL(p) {
			return false
		}
	}
	return len(p.planes) > 0
}

// Called on receive and timer ticks. Inactive inbound QPs do not probe; data
// sent in the current RTT supplies health feedback instead of extra probes.
func (e *Engine) pendingMRC(p *mrcReversePeer) bool {
	for _, srv6 := range []bool{false, true} {
		c := e.mrcInbound[receiverFlowKey{proto: "mrc", encap: p.key.encap, src: p.key.peer, dst: p.key.local, qp: p.key.qp, srv6: srv6}]
		if c != nil && c.pending > 0 {
			return true
		}
	}
	return false
}

func (e *Engine) serviceMRC(now time.Time) error {
	if !e.mrcReverseEnabled() {
		return nil
	}
	for key, pending := range e.mrcProbes {
		if now.Sub(pending.sent) > e.probeTimeout(pending.owner) {
			delete(e.mrcProbes, key)
		}
	}
	for _, p := range e.mrcReverse {
		if !p.lastInbound.IsZero() && (now.Sub(p.lastInbound) <= p.rtt || e.pendingMRC(p)) &&
			(p.lastOutbound.IsZero() || now.Sub(p.lastOutbound) >= p.rtt || !e.allPlanesConfirmed(p, now)) && (p.lastProbe.IsZero() || now.Sub(p.lastProbe) >= p.rtt) {
			if err := e.sendEVProbe(p, now); err != nil {
				return err
			}
			p.lastProbe = now
		}
	}
	for _, c := range e.mrcInbound {
		if c.pending > 0 {
			if err := e.receiverACK(c); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *Engine) noteMRCData(opts wire.BuildOpts, qp, psn uint32, now time.Time) {
	if !e.mrcReverseEnabled() {
		return
	}
	p := e.reversePeer(mrcReverseKey{opts.SrcIP, opts.DstIP, opts.Encap, qp})
	if p == nil {
		return
	}
	p.lastOutbound = now
	for seq, sent := range p.sent {
		if now.Sub(sent.at) > e.probeTimeout(p) {
			delete(p.sent, seq)
		}
	}
	_, exists := p.sent[psn]
	if exists || len(p.sent) < max(1, e.cfg.Window) {
		p.sent[psn] = mrcSent{uint32(opts.Entropy), now}
	}
}
func mrcAcked(psn uint32, f *wire.Frame) bool {
	if psn < f.CumAck {
		return true
	}
	delta := psn - f.CumAck
	return delta >= 1 && delta <= 64 && f.Bitmap&(uint64(1)<<(delta-1)) != 0
}
func (e *Engine) noteMRCSACK(f *wire.Frame, now time.Time) {
	p := e.mrcReverse[mrcReverseKey{f.DstIP, f.SrcIP, f.Encap, f.QP}]
	if p == nil {
		return
	}
	if f.Congestion != 0 {
		e.invalidateMRCProof(p, f.ReflectedEV)
	}
	for psn, sent := range p.sent {
		if mrcAcked(psn, f) {
			if psn == f.AckPSN && f.Congestion == 0 && sent.ev == f.ReflectedEV && now.Sub(sent.at) <= e.probeTimeout(p) && sent.ev >= 10000 && int(sent.ev-10000) < len(e.paths) {
				path := int(sent.ev - 10000)
				p.good[e.pathPlane(path)] = mrcProof{path, now}
				e.stats.ReverseEVDataUpdates.Add(1)
				p.sampleRTT(now.Sub(sent.at))
			}
			delete(p.sent, psn)
		}
	}
}

func (e *Engine) invalidateMRCProof(p *mrcReversePeer, ev uint32) {
	if ev < 10000 || int(ev-10000) >= len(e.paths) {
		return
	}
	path := int(ev - 10000)
	plane := e.pathPlane(path)
	if proof, ok := p.good[plane]; ok && proof.path == path {
		delete(p.good, plane)
	}
}

func (e *Engine) localMRC(f *wire.Frame) bool {
	for _, ip := range e.receiverIPs() {
		if f.DstIP == ip {
			return true
		}
	}
	return false
}

// Shared by send and receive loops, so a sending endpoint also responds to EV
// probes and can ACK inbound MRC data on the same QP during bidirectional use.
func (e *Engine) handleMRC(f *wire.Frame, now time.Time) (bool, error) {
	if !e.mrcReverseEnabled() || f.Proto != "mrc" || !e.localMRC(f) || !e.acceptsEncap(f.Encap) {
		return false, nil
	}
	switch f.Type {
	case wire.TypeNACK:
		p := e.mrcReverse[mrcReverseKey{f.DstIP, f.SrcIP, f.Encap, f.QP}]
		if p != nil {
			if sent, ok := p.sent[f.PSN]; ok && sent.ev == f.ReflectedEV {
				e.invalidateMRCProof(p, f.ReflectedEV)
			}
		}
		return true, nil
	case wire.TypeEVProbe:
		key := mrcReverseKey{f.DstIP, f.SrcIP, f.Encap, e.cfg.QP}
		path, ok := 0, false
		// Endpoint requests carry no data QP. Reuse a confirmed route from
		// any QP for these endpoints rather than assuming the CLI's QP.
		for peerKey, p := range e.mrcReverse {
			if peerKey.local == key.local && peerKey.peer == key.peer && peerKey.encap == key.encap {
				if selected, confirmed := e.confirmedPath(p, now); confirmed {
					path, ok = selected, true
					break
				}
			}
		}
		if !ok {
			path = rand.IntN(len(e.paths))
		} // probe replies bootstrap reachability; never mark this candidate healthy
		opts, err := e.mrcOpts(key, path)
		if err != nil {
			return true, err
		}
		raw, err := wire.BuildMRCFrame(opts, wire.EncodeMRCEVProbe(f.ProbeID, true))
		if err != nil {
			return true, err
		}
		return true, e.sock.Send(raw)
	case wire.TypeEVProbeReply:
		key := mrcProbeKey{f.DstIP, f.SrcIP, f.Encap, f.ProbeID}
		pending, ok := e.mrcProbes[key]
		if ok && now.Sub(pending.sent) <= e.probeTimeout(pending.owner) {
			p := pending.owner
			p.good[e.pathPlane(pending.path)] = mrcProof{pending.path, now}
			p.sampleRTT(now.Sub(pending.sent))
			delete(e.mrcProbes, key)
			e.stats.EVProbesAcked.Add(1)
		}
		return true, nil
	case wire.TypeData:
		if !e.cfg.AcceptAnyQP && f.QP != e.cfg.QP {
			return false, nil
		}
		key := receiverFlowKey{proto: "mrc", encap: f.Encap, src: f.SrcIP, dst: f.DstIP, qp: f.QP, srv6: f.OuterSRv6}
		if e.mrcInbound == nil {
			e.mrcInbound = make(map[receiverFlowKey]*falconConnection)
		}
		c := e.mrcInbound[key]
		if c == nil {
			if len(e.mrcInbound) >= maxReceiverFlows {
				return true, nil
			}
			c = &falconConnection{peer: f.SrcIP, localIP: f.DstIP, encap: f.Encap, remoteCID: f.QP, tracker: NewRecvTracker()}
			e.mrcInbound[key] = c
		}
		p := e.reversePeer(mrcReverseKey{f.DstIP, f.SrcIP, f.Encap, f.QP})
		if p == nil {
			return true, fmt.Errorf("MRC reverse peer limit reached")
		}
		p.lastInbound = now
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
		if p.lastProbe.IsZero() || now.Sub(p.lastProbe) >= p.rtt {
			if err := e.serviceMRC(now); err != nil {
				return true, err
			}
		}
		if c.pending >= e.cfg.SackEvery {
			return true, e.receiverACK(c)
		}
		return true, nil
	}
	return false, nil
}
