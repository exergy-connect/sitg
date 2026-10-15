package engine

import (
	"net"
	"net/netip"
	"testing"

	"github.com/jbemmel/sitg/internal/config"
	"github.com/jbemmel/sitg/internal/link"
)

func TestBuildOptsUsesOuterSRv6NextHop(t *testing.T) {
	inner := netip.MustParseAddr("192.0.2.2")
	outer := netip.MustParseAddr("fc00:0:100::")
	innerMAC := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	outerMAC := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	e := &Engine{
		cfg:    &config.Config{Encap: config.EncapUDP4, Entropy: config.EntropySRv6},
		ep:     &link.Endpoint{SrcIPv4: netip.MustParseAddr("192.0.2.1"), SrcIPv6: netip.MustParseAddr("2001:db8::1")},
		paths:  []netip.Addr{outer},
		dstMAC: map[netip.Addr]net.HardwareAddr{inner: innerMAC, outer: outerMAC},
	}
	opts, err := e.buildOpts(inner, 10000, 0)
	if err != nil {
		t.Fatal(err)
	}
	if opts.DstMAC.String() != outerMAC.String() || opts.DstIP != inner || opts.SRv6Dst != outer {
		t.Fatalf("incorrect SRv6 next hop: %+v", opts)
	}
}
