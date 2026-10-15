package wire

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestFalconPushLayout(t *testing.T) {
	// OCP v1.1 figure 17: version/CID, function/type, window bases, PSN, RSN.
	want, _ := hex.DecodeString("101234560000004a000000000000000001020304050607080003616263")
	got := EncodeFalconData(0x01020304, 0x123456, 0x05060708, []byte("abc"))
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
	f, err := DecodeFalconTransport(want)
	if err != nil {
		t.Fatal(err)
	}
	if f.QP != 0x123456 || f.PSN != 0x01020304 || f.MsgID != 0x05060708 || f.Length != 3 || string(f.Payload) != "abc" {
		t.Fatalf("%+v", f)
	}
}

func TestFalconACKLayout(t *testing.T) {
	bm := uint64(1) | uint64(1)<<62 | uint64(1)<<63
	b := EncodeFalconSACK(7, 42, bm)
	if len(b) != 72 || b[7] != 0x14 || b[11] != 42 || b[32] != 0x40 || b[39] != 1 || b[40] != 0x80 || !bytes.Equal(b[32:48], b[48:64]) {
		t.Fatalf("bad EACK %x", b)
	}
	f, err := DecodeFalconTransport(b)
	if err != nil || f.CumAck != 42 || f.Bitmap != bm || f.Type != TypeSACK {
		t.Fatalf("%+v %v", f, err)
	}
	b = b[:32]
	b[7] = 0x12
	f, err = DecodeFalconTransport(b)
	if err != nil || f.CumAck != 42 || f.Bitmap != 0 {
		t.Fatalf("BACK: %+v %v", f, err)
	}
}

func TestFalconFraming(t *testing.T) {
	for _, encap := range []string{"udp4", "udp6"} {
		for _, srv6 := range []bool{false, true} {
			src, dst := "2001:db8::1", "2001:db8::2"
			if encap == "udp4" {
				src, dst = "192.0.2.1", "192.0.2.2"
			}
			opts := BuildOpts{SrcMAC: mac("02:00:00:00:00:01"), DstMAC: mac("02:00:00:00:00:02"), SrcIP: netip.MustParseAddr(src), DstIP: netip.MustParseAddr(dst), Encap: encap, Entropy: 12345, UseSRv6: srv6, SRv6SrcIP: netip.MustParseAddr("2001:db8::1"), SRv6Dst: netip.MustParseAddr("fc00::1")}
			for _, trans := range [][]byte{EncodeFalconData(9, 7, 2, []byte("payload")), EncodeFalconSACK(7, 10, 5)} {
				raw, err := BuildFalconFrame(opts, trans)
				if err != nil {
					t.Fatal(err)
				}
				f, err := ParseEthernetFrame(raw, 253)
				if err != nil {
					t.Fatal(err)
				}
				if f.Proto != "falcon" || f.QP != 7 || f.Encap != encap || f.Entropy != 12345 || f.OuterSRv6 != srv6 {
					t.Fatalf("%+v", f)
				}
				if f.Type == TypeData && string(f.Payload) != "payload" {
					t.Fatalf("%+v", f)
				}
			}
		}
	}
	for _, encap := range []string{"ip4", "ip6", "invalid"} {
		if _, err := BuildFalconFrame(BuildOpts{Encap: encap}, nil); err == nil {
			t.Fatal("accepted", encap)
		}
	}
}

func TestFalconMalformed(t *testing.T) {
	for _, b := range [][]byte{EncodeFalconData(1, 1, 1, []byte("abc")), EncodeFalconSACK(1, 1, 0)} {
		for n := 0; n < len(b); n++ {
			if _, err := DecodeFalconTransport(b[:n]); err == nil {
				t.Fatalf("accepted truncation %d of %d", n, len(b))
			}
		}
	}
	for _, change := range []func([]byte){func(b []byte) { b[0] = 0x20 }, func(b []byte) { b[7] = 0 }, func(b []byte) { b[7] = 0x6a }} {
		b := EncodeFalconData(1, 1, 1, nil)
		change(b)
		if _, err := DecodeFalconTransport(b); err == nil {
			t.Fatalf("accepted %x", b)
		}
	}
}
