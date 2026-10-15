//go:build linux

package link

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ResolveDestinationMAC uses the kernel route and interface-scoped neighbor
// table. A short UDP probe lets the kernel perform ARP/NDP on a cold cache.
func ResolveDestinationMAC(ep *Endpoint, dst netip.Addr, timeout time.Duration) (net.HardwareAddr, error) {
	if ep.Iface.Flags&net.FlagLoopback != 0 {
		return make(net.HardwareAddr, 6), nil
	}
	src := ep.SrcIPv6
	if dst.Is4() {
		src = ep.SrcIPv4
	}
	routes, err := netlink.RouteGetWithOptions(net.IP(dst.AsSlice()), &netlink.RouteGetOptions{
		OifIndex: ep.Index, SrcAddr: net.IP(src.AsSlice()),
	})
	if err != nil {
		return nil, fmt.Errorf("route to %s on %s: %w", dst, ep.Iface.Name, err)
	}
	next, err := routeNextHop(routes, ep.Index, dst)
	if err != nil {
		return nil, err
	}
	family := unix.AF_INET6
	if next.Is4() {
		family = unix.AF_INET
	}
	lookup := func() (net.HardwareAddr, error) {
		neighbors, err := netlink.NeighList(ep.Index, family)
		if err != nil {
			return nil, err
		}
		return neighborMAC(neighbors, ep.Index, next), nil
	}
	if mac, err := lookup(); err != nil || mac != nil {
		return mac, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// Bind to the selected interface so overlapping addresses and management
	// routes cannot resolve a neighbor on a different link.
	dialer := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		var bindErr error
		if err := c.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ep.Iface.Name)
		}); err != nil {
			return err
		}
		return bindErr
	}}
	probeAddr := next
	if next.IsLinkLocalUnicast() && next.Is6() {
		probeAddr = next.WithZone(ep.Iface.Name)
	}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(probeAddr.String(), "9"))
	if err != nil {
		return nil, fmt.Errorf("neighbor discovery for %s on %s: %w", next, ep.Iface.Name, err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(nil); err != nil {
		return nil, fmt.Errorf("neighbor probe for %s: %w", next, err)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if mac, err := lookup(); err != nil || mac != nil {
			return mac, err
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("neighbor discovery for %s on %s: %w", next, ep.Iface.Name, ctx.Err())
		case <-ticker.C:
		}
	}
}

func routeNextHop(routes []netlink.Route, index int, dst netip.Addr) (netip.Addr, error) {
	for _, r := range routes {
		if r.LinkIndex != index || (r.Type != unix.RTN_UNICAST && r.Type != unix.RTN_LOCAL) {
			continue
		}
		gw := r.Gw
		if via, ok := r.Via.(*netlink.Via); ok {
			gw = via.Addr
		}
		if len(gw) == 0 {
			return dst, nil
		}
		if addr, ok := netip.AddrFromSlice(gw); ok {
			return addr.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no usable route to %s on interface index %d", dst, index)
}

func neighborMAC(neighbors []netlink.Neigh, index int, ip netip.Addr) net.HardwareAddr {
	const usable = unix.NUD_REACHABLE | unix.NUD_STALE | unix.NUD_DELAY | unix.NUD_PROBE | unix.NUD_PERMANENT | unix.NUD_NOARP
	for _, n := range neighbors {
		if n.LinkIndex == index && n.IP.Equal(net.IP(ip.AsSlice())) && n.State&usable != 0 && len(n.HardwareAddr) == 6 {
			mac := n.HardwareAddr
			if mac[0]&1 == 0 && (mac[0]|mac[1]|mac[2]|mac[3]|mac[4]|mac[5]) != 0 {
				return append(net.HardwareAddr(nil), mac...)
			}
		}
	}
	return nil
}
