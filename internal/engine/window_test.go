package engine

import (
	"testing"
	"time"
)

func TestRecvTrackerContiguous(t *testing.T) {
	r := NewRecvTracker()
	for _, psn := range []uint32{0, 1, 2} {
		dup, cum, _ := r.Observe(psn)
		if dup {
			t.Fatalf("unexpected dup %d", psn)
		}
		if cum != psn+1 {
			t.Fatalf("cum=%d after %d", cum, psn)
		}
	}
}

func TestRecvTrackerSelectiveBitmap(t *testing.T) {
	r := NewRecvTracker()
	r.Observe(0)
	// skip 1, receive 2 and 3
	dup, cum, bm := r.Observe(2)
	if dup || cum != 1 {
		t.Fatalf("cum=%d dup=%v", cum, dup)
	}
	_, cum, bm = r.Observe(3)
	if cum != 1 {
		t.Fatalf("cum still 1, got %d", cum)
	}
	// bit0 = cumAck+1 = 2, bit1 = 3
	if bm&(1<<0) == 0 || bm&(1<<1) == 0 {
		t.Fatalf("bitmap %#x", bm)
	}
	// fill hole
	_, cum, bm = r.Observe(1)
	if cum != 4 {
		t.Fatalf("after fill cum=%d bm=%#x", cum, bm)
	}
}

func TestRecvTrackerDuplicate(t *testing.T) {
	r := NewRecvTracker()
	r.Observe(0)
	dup, _, _ := r.Observe(0)
	if !dup {
		t.Fatal("expected duplicate")
	}
}

func TestSendWindowApplySACK(t *testing.T) {
	w := NewSendWindow(16, time.Millisecond)
	for i := uint32(0); i < 5; i++ {
		psn := w.NextPSN()
		w.Track(&Inflight{PSN: psn, Bytes: 100, SentAt: time.Now()})
	}
	acked, n, _ := w.ApplySACK(3, 0, time.Now())
	if n != 3 || acked != 300 {
		t.Fatalf("acked bytes=%d n=%d", acked, n)
	}
	if w.Len() != 2 {
		t.Fatalf("len=%d", w.Len())
	}
	// selective ack PSN 4 (cumAck=3 => bit0 = 4)
	acked, n, _ = w.ApplySACK(3, 1<<0, time.Now())
	if n != 1 || acked != 100 {
		t.Fatalf("selective acked=%d n=%d", acked, n)
	}
}

func TestSendWindowExpiredRetransmit(t *testing.T) {
	w := NewSendWindow(8, 2*time.Millisecond)
	psn0 := w.NextPSN()
	psn1 := w.NextPSN()
	w.Track(&Inflight{PSN: psn1, Bytes: 10, SentAt: time.Now().Add(-10 * time.Millisecond)})
	w.Track(&Inflight{PSN: psn0, Bytes: 10, SentAt: time.Now().Add(-10 * time.Millisecond)})
	exp := w.OldestExpired(time.Now())
	if exp == nil || exp.PSN != psn0 {
		t.Fatalf("expected oldest psn %d got %#v", psn0, exp)
	}
	w.MarkRetransmit(psn0, time.Now())
	exp = w.OldestExpired(time.Now())
	if exp == nil || exp.PSN != psn1 {
		t.Fatalf("expected next hole %d got %#v", psn1, exp)
	}
}

func TestSendWindowCanSend(t *testing.T) {
	w := NewSendWindow(2, time.Millisecond)
	if !w.CanSend() {
		t.Fatal("empty should can send")
	}
	w.Track(&Inflight{PSN: w.NextPSN(), SentAt: time.Now()})
	w.Track(&Inflight{PSN: w.NextPSN(), SentAt: time.Now()})
	if w.CanSend() {
		t.Fatal("full window")
	}
}
