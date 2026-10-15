package engine

import (
	"sync"
	"time"
)

// Inflight tracks a sent packet awaiting ACK.
type Inflight struct {
	PSN       uint32
	Payload   []byte
	MsgID     uint32
	Offset    uint32
	Length    uint32
	SentAt    time.Time
	Deadline  time.Duration
	Retries   int
	Bytes     int
	DstIndex  int
	PathIndex int
	DstIP     string
}

// SendWindow is a sliding window of outstanding packets.
type SendWindow struct {
	mu       sync.Mutex
	capacity int
	nextPSN  uint32
	cumAck   uint32 // highest contiguous PSN acknowledged (exclusive: next expected)
	slots    map[uint32]*Inflight
	rto      time.Duration
}

func NewSendWindow(capacity int, rto time.Duration) *SendWindow {
	return &SendWindow{
		capacity: capacity,
		slots:    make(map[uint32]*Inflight),
		rto:      rto,
		cumAck:   0,
		nextPSN:  0,
	}
}

func (w *SendWindow) CanSend() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.slots) < w.capacity
}

func (w *SendWindow) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.slots)
}

func (w *SendWindow) NextPSN() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	psn := w.nextPSN
	w.nextPSN++
	return psn
}

func (w *SendWindow) Track(pkt *Inflight) {
	w.mu.Lock()
	defer w.mu.Unlock()
	pkt.Deadline = w.rto
	w.slots[pkt.PSN] = pkt
}

// ApplySACK advances cumAck and frees acknowledged packets.
// bitmap bit i means cumAck+1+i was received (selective).
// sampleRTT is the age of the newest newly-acked packet (best RTT sample).
func (w *SendWindow) ApplySACK(cumAck uint32, bitmap uint64, now time.Time) (ackedBytes uint64, newlyAcked int, sampleRTT time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Ignore ACKs beyond anything this sender has transmitted.
	if cumAck > w.nextPSN {
		return 0, 0, 0
	}
	var newest time.Time
	take := func(pkt *Inflight) {
		ackedBytes += uint64(pkt.Bytes)
		newlyAcked++
		if newest.IsZero() || pkt.SentAt.After(newest) {
			newest = pkt.SentAt
		}
	}
	if cumAck > w.cumAck {
		for psn := w.cumAck; psn < cumAck; psn++ {
			if pkt, ok := w.slots[psn]; ok {
				take(pkt)
				delete(w.slots, psn)
			}
		}
		w.cumAck = cumAck
	}
	for i := 0; i < 64; i++ {
		if bitmap&(1<<uint(i)) == 0 {
			continue
		}
		psn := cumAck + 1 + uint32(i)
		if pkt, ok := w.slots[psn]; ok {
			take(pkt)
			delete(w.slots, psn)
		}
	}
	if !newest.IsZero() {
		sampleRTT = now.Sub(newest)
	}
	return ackedBytes, newlyAcked, sampleRTT
}

// OldestExpired returns the lowest-PSN packet past its RTO deadline, if any.
func (w *SendWindow) OldestExpired(now time.Time) *Inflight {
	w.mu.Lock()
	defer w.mu.Unlock()
	var oldest *Inflight
	for _, pkt := range w.slots {
		deadline := pkt.SentAt.Add(pkt.Deadline)
		if !now.After(deadline) {
			continue
		}
		if oldest == nil || pkt.PSN < oldest.PSN {
			oldest = pkt
		}
	}
	return oldest
}

func (w *SendWindow) MarkRetransmit(psn uint32, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	pkt, ok := w.slots[psn]
	if !ok {
		return
	}
	pkt.Retries++
	pkt.SentAt = now
	// linear then exponential
	if pkt.Retries <= 3 {
		pkt.Deadline = w.rto * time.Duration(pkt.Retries+1)
	} else {
		pkt.Deadline = w.rto * time.Duration(1<<uint(pkt.Retries-2))
		if pkt.Deadline > 100*time.Millisecond {
			pkt.Deadline = 100 * time.Millisecond
		}
	}
}

func (w *SendWindow) Empty() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.slots) == 0
}

func (w *SendWindow) OldestRTT(now time.Time) time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	var oldest time.Time
	for _, pkt := range w.slots {
		if oldest.IsZero() || pkt.SentAt.Before(oldest) {
			oldest = pkt.SentAt
		}
	}
	if oldest.IsZero() {
		return 0
	}
	return now.Sub(oldest)
}

// RecvTracker tracks received PSNs for SACK generation.
type RecvTracker struct {
	mu     sync.Mutex
	cumAck uint32 // next expected PSN (exclusive received contiguous)
	bitmap uint64 // bits for cumAck+1 .. cumAck+64
	seen   map[uint32]struct{}
	maxPSN uint32
	hasMax bool
}

func NewRecvTracker() *RecvTracker {
	return &RecvTracker{seen: make(map[uint32]struct{})}
}

// Observe records a PSN. Returns true if it was a duplicate.
func (r *RecvTracker) Observe(psn uint32) (duplicate bool, cumAck uint32, bitmap uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if psn < r.cumAck {
		return true, r.cumAck, r.bitmap
	}
	if _, ok := r.seen[psn]; ok {
		return true, r.cumAck, r.bitmap
	}
	r.seen[psn] = struct{}{}
	if !r.hasMax || psn > r.maxPSN {
		r.maxPSN = psn
		r.hasMax = true
	}
	if psn == r.cumAck {
		delete(r.seen, psn)
		r.cumAck++
		for {
			if _, ok := r.seen[r.cumAck]; !ok {
				break
			}
			delete(r.seen, r.cumAck)
			r.cumAck++
		}
	}
	r.rebuildBitmap()
	r.pruneSeen()
	return false, r.cumAck, r.bitmap
}

func (r *RecvTracker) rebuildBitmap() {
	var bm uint64
	for i := uint32(0); i < 64; i++ {
		if _, ok := r.seen[r.cumAck+1+i]; ok {
			bm |= 1 << i
		}
	}
	r.bitmap = bm
}

// pruneSeen drops tracked PSNs far beyond the SACK bitmap horizon to bound memory.
func (r *RecvTracker) pruneSeen() {
	const horizon = 4096
	for psn := range r.seen {
		if psn > r.cumAck+horizon {
			delete(r.seen, psn)
		}
	}
}

func (r *RecvTracker) Snapshot() (cumAck uint32, bitmap uint64, gaps int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Gaps = missing PSNs in [cumAck, maxPSN].
	if r.hasMax && r.maxPSN >= r.cumAck {
		span := int(r.maxPSN - r.cumAck + 1)
		held := len(r.seen)
		gaps = span - held
		if gaps < 0 {
			gaps = 0
		}
	}
	return r.cumAck, r.bitmap, gaps
}

// ClearPSN returns the inclusive PSN whose ACK has been received.
func (w *SendWindow) ClearPSN() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cumAck - 1
}
