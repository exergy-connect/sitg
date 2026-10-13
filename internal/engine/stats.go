package engine

import (
	"fmt"
	"sync/atomic"
	"time"
)

// Stats tracks session counters for sender or receiver.
type Stats struct {
	role string

	PacketsSent   atomic.Uint64
	Retransmits   atomic.Uint64
	PacketsRecv   atomic.Uint64
	Duplicates    atomic.Uint64
	RTXFlagged    atomic.Uint64
	SACKsSent     atomic.Uint64
	SACKsRecv     atomic.Uint64
	BytesSent     atomic.Uint64
	BytesAcked    atomic.Uint64
	BytesUnique   atomic.Uint64
	GapsOpen      atomic.Uint64

	rttCount atomic.Uint64
	rttSumNs atomic.Uint64
	rttMinNs atomic.Uint64
	rttMaxNs atomic.Uint64

	start atomic.Int64 // unix nano of first packet
	end   atomic.Int64
}

func NewStats(role string) *Stats {
	s := &Stats{role: role}
	s.rttMinNs.Store(^uint64(0))
	return s
}

func (s *Stats) MarkStart() {
	if s.start.Load() == 0 {
		s.start.CompareAndSwap(0, time.Now().UnixNano())
	}
}

func (s *Stats) MarkEnd() {
	s.end.Store(time.Now().UnixNano())
}

func (s *Stats) Elapsed() time.Duration {
	start := s.start.Load()
	if start == 0 {
		return 0
	}
	end := s.end.Load()
	if end == 0 {
		end = time.Now().UnixNano()
	}
	return time.Duration(end - start)
}

func (s *Stats) ObserveRTT(d time.Duration) {
	ns := uint64(d.Nanoseconds())
	if ns == 0 {
		return
	}
	s.rttSumNs.Add(ns)
	s.rttCount.Add(1)
	for {
		cur := s.rttMinNs.Load()
		if ns >= cur || s.rttMinNs.CompareAndSwap(cur, ns) {
			break
		}
	}
	for {
		cur := s.rttMaxNs.Load()
		if ns <= cur || s.rttMaxNs.CompareAndSwap(cur, ns) {
			break
		}
	}
}

func (s *Stats) ProgressLine() string {
	elapsed := s.Elapsed()
	if s.role == "send" {
		sent := s.PacketsSent.Load()
		rtx := s.Retransmits.Load()
		acked := s.BytesAcked.Load()
		loss := 0.0
		if sent > 0 {
			loss = float64(rtx) / float64(sent) * 100
		}
		goodput := 0.0
		if elapsed > 0 {
			goodput = float64(acked*8) / elapsed.Seconds() / 1e9
		}
		return fmt.Sprintf("send: pkts=%d rtx=%d sack=%d acked=%dB loss=%.2f%% goodput=%.3fGbps t=%s",
			sent, rtx, s.SACKsRecv.Load(), acked, loss, goodput, elapsed.Round(time.Millisecond))
	}
	recv := s.PacketsRecv.Load()
	uniq := s.BytesUnique.Load()
	goodput := 0.0
	if elapsed > 0 {
		goodput = float64(uniq*8) / elapsed.Seconds() / 1e9
	}
	return fmt.Sprintf("recv: pkts=%d dup=%d rtx=%d sack=%d uniq=%dB gaps=%d goodput=%.3fGbps t=%s",
		recv, s.Duplicates.Load(), s.RTXFlagged.Load(), s.SACKsSent.Load(), uniq,
		s.GapsOpen.Load(), goodput, elapsed.Round(time.Millisecond))
}

func (s *Stats) FinalReport() string {
	elapsed := s.Elapsed()
	if s.role == "send" {
		sent := s.PacketsSent.Load()
		rtx := s.Retransmits.Load()
		loss := 0.0
		if sent > 0 {
			loss = float64(rtx) / float64(sent) * 100
		}
		goodput := 0.0
		if elapsed > 0 {
			goodput = float64(s.BytesAcked.Load()*8) / elapsed.Seconds() / 1e9
		}
		min, mean, max := s.rttSummary()
		return fmt.Sprintf(
			"=== sender final ===\n"+
				"packets sent: %d (retransmissions: %d)\n"+
				"SACKs received: %d\n"+
				"bytes sent: %d\n"+
				"bytes acknowledged: %d\n"+
				"inferred loss: %.2f%%\n"+
				"goodput: %.3f Gbps\n"+
				"SACK RTT: min=%s mean=%s max=%s\n"+
				"total time: %s\n",
			sent, rtx, s.SACKsRecv.Load(), s.BytesSent.Load(), s.BytesAcked.Load(),
			loss, goodput, min, mean, max, elapsed.Round(time.Microsecond),
		)
	}
	goodput := 0.0
	if elapsed > 0 {
		goodput = float64(s.BytesUnique.Load()*8) / elapsed.Seconds() / 1e9
	}
	return fmt.Sprintf(
		"=== receiver final ===\n"+
			"packets received: %d (duplicates: %d, rtx-flagged: %d)\n"+
			"SACKs sent: %d\n"+
			"bytes received (unique): %d\n"+
			"gaps open: %d\n"+
			"goodput: %.3f Gbps\n"+
			"total time: %s\n",
		s.PacketsRecv.Load(), s.Duplicates.Load(), s.RTXFlagged.Load(),
		s.SACKsSent.Load(), s.BytesUnique.Load(), s.GapsOpen.Load(),
		goodput, elapsed.Round(time.Microsecond),
	)
}

func (s *Stats) rttSummary() (min, mean, max string) {
	count := s.rttCount.Load()
	if count == 0 {
		return "n/a", "n/a", "n/a"
	}
	minNs := s.rttMinNs.Load()
	if minNs == ^uint64(0) {
		minNs = 0
	}
	meanNs := s.rttSumNs.Load() / count
	maxNs := s.rttMaxNs.Load()
	return time.Duration(minNs).String(), time.Duration(meanNs).String(), time.Duration(maxNs).String()
}
