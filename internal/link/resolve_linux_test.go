//go:build linux

package link

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestRouteNextHop(t *testing.T) {
	for _, tc := range []struct {
		name, dst, gateway, want string
		index, kind              int
	}{
		{"direct4", "192.0.2.2", "", "192.0.2.2", 7, unix.RTN_UNICAST},
		{"routed4", "198.51.100.2", "192.0.2.1", "192.0.2.1", 7, unix.RTN_UNICAST},
		{"direct6", "2001:db8::2", "", "2001:db8::2", 7, unix.RTN_UNICAST},
		{"routed6", "2001:db8:1::2", "fe80::1", "fe80::1", 7, unix.RTN_UNICAST},
		{"wrong-interface", "192.0.2.2", "192.0.2.1", "", 8, unix.RTN_UNICAST},
		{"blackhole", "192.0.2.2", "", "", 7, unix.RTN_BLACKHOLE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := netlink.Route{LinkIndex: tc.index, Type: tc.kind, Gw: net.ParseIP(tc.gateway)}
			got, err := routeNextHop([]netlink.Route{route}, 7, netip.MustParseAddr(tc.dst))
			if tc.want == "" {
				if err == nil {
					t.Fatal("expected route rejection")
				}
				return
			}
			if err != nil || got.String() != tc.want {
				t.Fatalf("got %s, %v; want %s", got, err, tc.want)
			}
		})
	}
}

func TestNeighborMACIsScopedAndUsable(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	for _, state := range []int{unix.NUD_REACHABLE, unix.NUD_STALE, unix.NUD_PERMANENT, unix.NUD_INCOMPLETE, unix.NUD_FAILED} {
		entries := []netlink.Neigh{
			{LinkIndex: 8, IP: net.IP(ip.AsSlice()), State: unix.NUD_REACHABLE, HardwareAddr: mac},
			{LinkIndex: 7, IP: net.ParseIP("192.0.2.9"), State: unix.NUD_REACHABLE, HardwareAddr: mac},
			{LinkIndex: 7, IP: net.IP(ip.AsSlice()), State: state, HardwareAddr: mac},
		}
		got := neighborMAC(entries, 7, ip)
		want := state != unix.NUD_INCOMPLETE && state != unix.NUD_FAILED
		if (got != nil) != want {
			t.Fatalf("state %d: got %v", state, got)
		}
	}
}
