package wire

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

func TestNativeSRv6TerminalIntegrity(t *testing.T) {
	terminal := netip.MustParseAddr("5f00:0:300::42:0")
	opts := BuildOpts{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, SrcIP: netip.MustParseAddr("5f00:0:200::1"), DstIP: terminal, Encap: "udp6", Entropy: 10000, IPProto: 253}
	for _, proto := range []string{"mrc", "uet", "falcon"} {
		t.Run(proto, func(t *testing.T) {
			var build func(BuildOpts, []byte) ([]byte, error)
			switch proto {
			case "mrc":
				build = BuildMRCFrame
			case "uet":
				build = BuildUETFrame
			case "falcon":
				build = BuildFalconFrame
			}
			payload := make([]byte, 128)
			plain, err := build(opts, payload)
			if err != nil {
				t.Fatal(err)
			}
			nativeOpts := opts
			nativeOpts.UseSRv6 = true
			nativeOpts.NativeSRv6 = true
			nativeOpts.SRv6Dst = netip.MustParseAddr("5f00:0:500:300::42")
			raw, err := build(nativeOpts, payload)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != len(plain) || raw[20] != IPProtoUDP {
				t.Fatal("native mode added a header")
			}
			// Simulate one F3216 NEXT-CSID advancement at the spine.
			da := raw[38:54]
			copy(da[4:14], da[6:16])
			da[14], da[15] = 0, 0
			if !bytes.Equal(da, terminal.AsSlice()) {
				t.Fatal("incorrect terminal address")
			}
			if UDPChecksumIPv6(opts.SrcIP, terminal, uint16(len(raw)-54), raw[54:]) != 0xffff {
				t.Fatal("invalid terminal UDP checksum")
			}
			if proto != "uet" && !bytes.Equal(raw, plain) {
				t.Fatal("terminal packet differs from ordinary IPv6 packet, including transport integrity")
			}
			if proto == "uet" && !bytes.Equal(raw[len(raw)-4:], plain[len(plain)-4:]) {
				t.Fatal("UET integrity differs at terminal")
			}
			if binary.BigEndian.Uint16(raw[60:62]) == 0 {
				t.Fatal("native IPv6 UDP checksum missing")
			}
		})
	}
}

func TestNativeSRv6UETIP6(t *testing.T) {
	opts := BuildOpts{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, SrcIP: netip.MustParseAddr("5f00:0:200::1:0"), DstIP: netip.MustParseAddr("5f00:0:300::42:0"), Encap: "ip6", IPProto: 253, UseSRv6: true, NativeSRv6: true, SRv6Dst: netip.MustParseAddr("5f00:0:500:300::42")}
	raw, err := BuildUETFrame(opts, make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != EthernetHeaderLen+IPv6HeaderLen+EntropyHeaderLen+64 || raw[20] != 253 {
		t.Fatal("wrong native IP6 framing")
	}
	for _, encap := range []string{"udp4", "ip4"} {
		opts.Encap = encap
		if _, err := BuildUETFrame(opts, make([]byte, 64)); err == nil {
			t.Fatal("accepted IPv4 native SRv6")
		}
	}
}
