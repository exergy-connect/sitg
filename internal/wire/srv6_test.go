package wire

import (
	"net/netip"
	"testing"
)

func TestEncodeUSID(t *testing.T) {
	p := PathParams{
		Locator:  netip.MustParseAddr("fc00::"),
		Paths:    64,
		Hops:     3,
		Radix:    32,
		USIDBase: 0x0100,
	}
	addr, err := EncodeUSID(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	hops, loc, err := DecodeUSIDHops(addr, 3)
	if err != nil {
		t.Fatal(err)
	}
	if loc != [4]byte{0xfc, 0x00, 0x00, 0x00} {
		t.Fatalf("locator %v", loc)
	}
	if hops[0] != 0x0100 || hops[1] != 0x0100 || hops[2] != 0x0100 {
		t.Fatalf("hops %v", hops)
	}

	addr33, err := EncodeUSID(p, 33)
	if err != nil {
		t.Fatal(err)
	}
	hops33, _, err := DecodeUSIDHops(addr33, 3)
	if err != nil {
		t.Fatal(err)
	}
	// 33 = 1*32 + 1 -> hop0 = base+1, hop1 = base+1
	if hops33[0] != 0x0101 {
		t.Fatalf("hop0=%#x", hops33[0])
	}
	if hops33[1] != 0x0101 {
		t.Fatalf("hop1=%#x", hops33[1])
	}
}

func TestAllPathsDistinct(t *testing.T) {
	p := PathParams{
		Locator:  netip.MustParseAddr("fc00:1::"),
		Paths:    16,
		Hops:     2,
		Radix:    8,
		USIDBase: 0x1000,
	}
	paths, err := AllPaths(p)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[netip.Addr]bool{}
	for _, a := range paths {
		if seen[a] {
			t.Fatalf("duplicate path %s", a)
		}
		seen[a] = true
	}
}

func TestSRv6OuterWrap(t *testing.T) {
	transport := EncodeUETData(1, 1, 1, 0, 3, false, []byte("xyz"))
	srv6, err := EncodeUSID(PathParams{
		Locator:  netip.MustParseAddr("fc00::"),
		Paths:    4,
		Hops:     2,
		Radix:    4,
		USIDBase: 0x0100,
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	opts := BuildOpts{
		SrcMAC:  mac("02:00:00:00:00:01"),
		DstMAC:  mac("02:00:00:00:00:02"),
		SrcIP:   netip.MustParseAddr("2001:db8::1"),
		DstIP:   netip.MustParseAddr("2001:db8::2"),
		Encap:   "udp6",
		Entropy: 7,
		UseSRv6: true,
		SRv6Dst: srv6,
	}
	frame, err := BuildUETFrame(opts, transport)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseEthernetFrame(frame, 253)
	if err != nil {
		t.Fatal(err)
	}
	if !f.OuterSRv6 {
		t.Fatal("expected OuterSRv6")
	}
	if f.OuterDst != srv6 {
		t.Fatalf("outer dst %s want %s", f.OuterDst, srv6)
	}
	if f.PSN != 1 || string(f.Payload) != "xyz" {
		t.Fatalf("%+v", f)
	}
}

func TestSRv6OuterWithInnerIPv4(t *testing.T) {
	transport := EncodeMRCData(1, 1, 1, 0, 1, false, []byte{0xaa})
	srv6 := netip.MustParseAddr("fc00:0:0100:0101::")
	opts := BuildOpts{
		SrcMAC:    mac("02:00:00:00:00:01"),
		DstMAC:    mac("02:00:00:00:00:02"),
		SrcIP:     netip.MustParseAddr("10.0.0.1"),
		DstIP:     netip.MustParseAddr("10.0.0.2"),
		Encap:     "udp4",
		Entropy:   9,
		UseSRv6:   true,
		SRv6Dst:   srv6,
		SRv6SrcIP: netip.MustParseAddr("2001:db8::1"),
	}
	frame, err := BuildMRCFrame(opts, transport)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseEthernetFrame(frame, 253)
	if err != nil {
		t.Fatal(err)
	}
	if !f.OuterSRv6 || f.Proto != "mrc" {
		t.Fatalf("%+v", f)
	}
}
