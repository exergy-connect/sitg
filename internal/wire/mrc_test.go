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
