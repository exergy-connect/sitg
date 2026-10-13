package wire

import (
	"net"
	"net/netip"
	"testing"
)

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func TestUETEncapsulationsRoundTrip(t *testing.T) {
	cases := []struct {
		encap string
		src   string
		dst   string
	}{
		{"udp6", "2001:db8::1", "2001:db8::2"},
		{"udp4", "10.0.0.1", "10.0.0.2"},
		{"ip6", "2001:db8::1", "2001:db8::2"},
		{"ip4", "10.0.0.1", "10.0.0.2"},
	}
	for _, tc := range cases {
		t.Run(tc.encap, func(t *testing.T) {
			src := netip.MustParseAddr(tc.src)
			dst := netip.MustParseAddr(tc.dst)
			payload := []byte("hello-uet")
			transport := EncodeUETData(42, 7, 1, 0, uint32(len(payload)), false, payload)
			opts := BuildOpts{
				SrcMAC:  mac("02:00:00:00:00:01"),
				DstMAC:  mac("02:00:00:00:00:02"),
				SrcIP:   src,
				DstIP:   dst,
				Encap:   tc.encap,
				IPProto: 253,
				Entropy: 12345,
			}
			frame, err := BuildUETFrame(opts, transport)
			if err != nil {
				t.Fatal(err)
			}
			f, err := ParseEthernetFrame(frame, 253)
			if err != nil {
				t.Fatal(err)
			}
			if f.Proto != "uet" || f.Type != TypeData {
				t.Fatalf("got proto=%s type=%v", f.Proto, f.Type)
			}
			if f.Encap != tc.encap {
				t.Fatalf("encap: got %s want %s", f.Encap, tc.encap)
			}
			if f.PSN != 42 || f.QP != 7 {
				t.Fatalf("psn/qp: %d/%d", f.PSN, f.QP)
			}
			if f.Entropy != 12345 {
				t.Fatalf("entropy: %d", f.Entropy)
			}
			if string(f.Payload) != "hello-uet" {
				t.Fatalf("payload %q", f.Payload)
			}
		})
	}
}

func TestUETSACKRoundTrip(t *testing.T) {
	transport := EncodeUETSACK(3, 100, 0b1011)
	opts := BuildOpts{
		SrcMAC:  mac("02:00:00:00:00:01"),
		DstMAC:  mac("02:00:00:00:00:02"),
		SrcIP:   netip.MustParseAddr("2001:db8::1"),
		DstIP:   netip.MustParseAddr("2001:db8::2"),
		Encap:   "udp6",
		Entropy: 99,
	}
	frame, err := BuildUETFrame(opts, transport)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseEthernetFrame(frame, 253)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TypeSACK || f.CumAck != 100 || f.Bitmap != 0b1011 || f.QP != 3 {
		t.Fatalf("sack fields: %+v", f)
	}
}

func TestUETUDPChecksumZero(t *testing.T) {
	transport := EncodeUETData(1, 1, 1, 0, 4, false, []byte("abcd"))
	opts := BuildOpts{
		SrcMAC:  mac("02:00:00:00:00:01"),
		DstMAC:  mac("02:00:00:00:00:02"),
		SrcIP:   netip.MustParseAddr("2001:db8::1"),
		DstIP:   netip.MustParseAddr("2001:db8::2"),
		Encap:   "udp6",
		Entropy: 1,
	}
	frame, err := BuildUETFrame(opts, transport)
	if err != nil {
		t.Fatal(err)
	}
	// UDP checksum at ethernet(14)+ipv6(40)+udp.checksum offset 6
	csum := uint16(frame[14+40+6])<<8 | uint16(frame[14+40+7])
	if csum != 0 {
		t.Fatalf("UET UDP checksum want 0 got %#x", csum)
	}
}
