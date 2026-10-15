package wire

import (
	"net/netip"
	"testing"
)

func TestMRCRoundTrip(t *testing.T) {
	payload := []byte("mrc-data")
	transport := EncodeMRCData(9, 5, 2, 64, 1024, true, payload)
	opts := BuildOpts{
		SrcMAC:  mac("02:00:00:00:00:01"),
		DstMAC:  mac("02:00:00:00:00:02"),
		SrcIP:   netip.MustParseAddr("2001:db8::1"),
		DstIP:   netip.MustParseAddr("2001:db8::2"),
		Encap:   "udp6",
		Entropy: 40000,
	}
	frame, err := BuildMRCFrame(opts, transport)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseEthernetFrame(frame, 253)
	if err != nil {
		t.Fatal(err)
	}
	if f.Proto != "mrc" || f.Type != TypeData {
		t.Fatalf("proto/type %s %v", f.Proto, f.Type)
	}
	if !f.RTX {
		t.Fatal("expected rtx")
	}
	if f.PSN != 9 || f.QP != 5 || f.MsgID != 2 || f.Offset != 64 {
		t.Fatalf("fields %+v", f)
	}
	if string(f.Payload) != "mrc-data" {
		t.Fatalf("payload %q", f.Payload)
	}
}

func TestMRCRejectsNativeEncap(t *testing.T) {
	opts := BuildOpts{
		SrcMAC: mac("02:00:00:00:00:01"),
		DstMAC: mac("02:00:00:00:00:02"),
		SrcIP:  netip.MustParseAddr("2001:db8::1"),
		DstIP:  netip.MustParseAddr("2001:db8::2"),
		Encap:  "ip6",
	}
	_, err := BuildMRCFrame(opts, EncodeMRCData(1, 1, 1, 0, 1, false, []byte{1}))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMRCSACK(t *testing.T) {
	transport := EncodeMRCSACK(1, 50, 0xff)
	opts := BuildOpts{
		SrcMAC:  mac("02:00:00:00:00:01"),
		DstMAC:  mac("02:00:00:00:00:02"),
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		DstIP:   netip.MustParseAddr("10.0.0.2"),
		Encap:   "udp4",
		Entropy: 1,
	}
	frame, err := BuildMRCFrame(opts, transport)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseEthernetFrame(frame, 253)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TypeSACK || f.CumAck != 50 || f.Bitmap != 0xff {
		t.Fatalf("%+v", f)
	}
}

func TestMRCStandardWireFields(t *testing.T) {
	for _, tc := range []struct {
		offset, length uint32
		opcode         byte
	}{{0, 3, 0xca}, {0, 9, 0xc6}, {3, 9, 0xc7}, {6, 9, 0xc8}, {70000, 70003, 0xc8}} {
		b := EncodeMRCData(12, 1, 9, tc.offset, tc.length, true, []byte("abc"))
		if b[0] != tc.opcode || b[1] != 0x10 || b[8] != 0xa0 || b[14] != 0 || b[15] != 9 {
			t.Fatalf("nonstandard BTH/METH %x", b)
		}
		f, err := DecodeMRCTransport(b)
		if err != nil || f.Offset != tc.offset || string(f.Payload) != "abc" || f.Length != tc.length {
			t.Fatalf("decode %+v %v", f, err)
		}
		for n := 0; n < 32+4; n++ {
			if _, err := DecodeMRCTransport(b[:n]); err == nil {
				t.Fatalf("accepted %d byte write", n)
			}
		}
	}
	for _, cum := range []uint32{0, 1, 13, 0xffffff} {
		b := EncodeMRCSACK(1, cum, 0xb, 10000)
		f, err := DecodeMRCTransport(b)
		if err != nil || f.CumAck != cum || f.Bitmap != 0xb {
			t.Fatalf("SACK translation %+v %v", f, err)
		}
		if b[0] != 0xdc || b[30] != 0 || b[31] != 2 {
			t.Fatalf("nonstandard SACK %x", b)
		}
	}
}
