//go:build linux

package link

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Endpoint holds resolved interface addressing.
type Endpoint struct {
	Iface    *net.Interface
	SrcMAC   net.HardwareAddr
	SrcIPv4  netip.Addr
	SrcIPv6  netip.Addr
	Index    int
}

// Socket is an AF_PACKET raw socket bound to an interface.
type Socket struct {
	fd  int
	ep  *Endpoint
}

// ResolveEndpoint looks up the interface and its addresses.
func ResolveEndpoint(ifaceName string) (*Endpoint, error) {
	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}
	ep := &Endpoint{
		Iface:  ifi,
		SrcMAC: append(net.HardwareAddr(nil), ifi.HardwareAddr...),
		Index:  ifi.Index,
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.Is4() && !ep.SrcIPv4.IsValid() && !addr.IsLinkLocalUnicast() {
			ep.SrcIPv4 = addr
		}
		if addr.Is6() && !addr.IsLinkLocalUnicast() && !ep.SrcIPv6.IsValid() {
			ep.SrcIPv6 = addr
		}
	}
	// Prefer global; fall back to link-local IPv6 if needed.
	if !ep.SrcIPv6.IsValid() {
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.Is6() && addr.IsLinkLocalUnicast() {
				ep.SrcIPv6 = addr
				break
			}
		}
	}
	return ep, nil
}

// OpenSocket opens AF_PACKET SOCK_RAW and attaches a BPF filter.
func OpenSocket(ep *Endpoint, ipProto uint8) (*Socket, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	s := &Socket{fd: fd, ep: ep}
	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ep.Index,
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}
	// Enlarge buffers to reduce drops under spray/retransmit load.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 32*1024*1024)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 32*1024*1024)
	if err := attachFilter(fd, ipProto); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bpf: %w", err)
	}
	return s, nil
}

func (s *Socket) Endpoint() *Endpoint { return s.ep }

func (s *Socket) Close() error {
	if s.fd >= 0 {
		err := unix.Close(s.fd)
		s.fd = -1
		return err
	}
	return nil
}

func (s *Socket) Send(frame []byte) error {
	sa := &unix.SockaddrLinklayer{
		Ifindex: s.ep.Index,
		Halen:   6,
	}
	copy(sa.Addr[:], s.ep.SrcMAC)
	return unix.Sendto(s.fd, frame, 0, sa)
}

func (s *Socket) Recv(buf []byte) (int, error) {
	n, _, err := unix.Recvfrom(s.fd, buf, 0)
	return n, err
}

func (s *Socket) SetNonblock(nonblock bool) error {
	return unix.SetNonblock(s.fd, nonblock)
}

func (s *Socket) FD() int { return s.fd }

// LookupNeighborMAC reads /proc/net/arp or /proc/net/ipv6_neigh-style via netlink-less heuristic:
// for IPv4 uses /proc/net/arp; for IPv6 scans /sys and neigh via ip neigh file if present.
func LookupNeighborMAC(ip netip.Addr) (net.HardwareAddr, error) {
	if ip.Is4() {
		return lookupIPv4ARP(ip)
	}
	return lookupIPv6Neigh(ip)
}

func lookupIPv4ARP(ip netip.Addr) (net.HardwareAddr, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	want := ip.String()
	lines := splitLines(data)
	for i, line := range lines {
		if i == 0 {
			continue
		}
		fields := fieldsWS(line)
		if len(fields) < 4 {
			continue
		}
		if fields[0] == want && fields[3] != "00:00:00:00:00:00" {
			mac, err := net.ParseMAC(fields[3])
			if err != nil {
				continue
			}
			return mac, nil
		}
	}
	return nil, fmt.Errorf("no ARP entry for %s", ip)
}

func lookupIPv6Neigh(ip netip.Addr) (net.HardwareAddr, error) {
	// Parse `ip -6 neigh` is not available without exec; use netlink GETNEIGH via raw syscall.
	mac, err := netlinkGetNeigh(ip)
	if err != nil {
		return nil, fmt.Errorf("no neighbor for %s: %w", ip, err)
	}
	return mac, nil
}

func netlinkGetNeigh(ip netip.Addr) (net.HardwareAddr, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, sa); err != nil {
		return nil, err
	}

	var family byte = unix.AF_INET6
	addrBytes := ip.AsSlice()
	if ip.Is4() {
		family = unix.AF_INET
	}

	const (
		NDA_DST = 1
		NDA_LLADDR = 2
		NLM_F_REQUEST = 0x1
		NLM_F_DUMP = 0x300
		RTM_GETNEIGH = 30
	)

	// ndmsg
	ndmsg := make([]byte, 12)
	ndmsg[0] = family

	attr := make([]byte, 4+len(addrBytes))
	binary.LittleEndian.PutUint16(attr[0:2], uint16(len(attr)))
	binary.LittleEndian.PutUint16(attr[2:4], NDA_DST)
	copy(attr[4:], addrBytes)
	// align to 4
	pad := (4 - (len(attr) % 4)) % 4
	attr = append(attr, make([]byte, pad)...)

	payload := append(ndmsg, attr...)
	nlmsgLen := 16 + len(payload)
	msg := make([]byte, nlmsgLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(nlmsgLen))
	binary.LittleEndian.PutUint16(msg[4:6], RTM_GETNEIGH)
	binary.LittleEndian.PutUint16(msg[6:8], NLM_F_REQUEST|NLM_F_DUMP)
	binary.LittleEndian.PutUint32(msg[8:12], 1) // seq
	copy(msg[16:], payload)

	if _, err := unix.Write(fd, msg); err != nil {
		return nil, err
	}

	buf := make([]byte, 8192)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			return nil, err
		}
		off := 0
		for off+16 <= n {
			mlen := int(binary.LittleEndian.Uint32(buf[off : off+4]))
			mtype := binary.LittleEndian.Uint16(buf[off+4 : off+6])
			if mlen < 16 || off+mlen > n {
				break
			}
			if mtype == unix.NLMSG_DONE {
				return nil, fmt.Errorf("not found")
			}
			if mtype == unix.NLMSG_ERROR {
				return nil, fmt.Errorf("netlink error")
			}
			if mtype == RTM_GETNEIGH+1 { // RTM_NEWNEIGH = 28, dump returns NEWNEIGH
				// actually RTM_NEWNEIGH is 28
			}
			const RTM_NEWNEIGH = 28
			if mtype == RTM_NEWNEIGH {
				body := buf[off+16 : off+mlen]
				if len(body) < 12 {
					off += (mlen + 3) & ^3
					continue
				}
				attrs := body[12:]
				var dst netip.Addr
				var lladdr net.HardwareAddr
				aoff := 0
				for aoff+4 <= len(attrs) {
					alen := int(binary.LittleEndian.Uint16(attrs[aoff : aoff+2]))
					atype := binary.LittleEndian.Uint16(attrs[aoff+2 : aoff+4])
					if alen < 4 || aoff+alen > len(attrs) {
						break
					}
					aval := attrs[aoff+4 : aoff+alen]
					switch atype {
					case NDA_DST:
						if addr, ok := netip.AddrFromSlice(aval); ok {
							dst = addr.Unmap()
						}
					case NDA_LLADDR:
						lladdr = append(net.HardwareAddr(nil), aval...)
					}
					aoff += (alen + 3) & ^3
				}
				if dst == ip && len(lladdr) >= 6 {
					return lladdr[:6], nil
				}
			}
			off += (mlen + 3) & ^3
		}
	}
}

func attachFilter(fd int, ipProto uint8) error {
	// Classic BPF: accept IPv4/IPv6 UDP ports 4791/4793, or IP proto == ipProto.
	// Filter at Ethernet level.
	//
	// Simplified filter program:
	// ldh [12]                  ; ethertype
	// jeq #0x0800, ipv4, check6
	// check6: jeq #0x86dd, ipv6, drop
	// ipv4: ldb [23]            ; protocol
	// jeq #17, udp4, check_native4
	// check_native4: jeq #ipProto, accept, drop
	// udp4: ldh [20+16+2]? wait offsets...
	//
	// For robustness we use a permissive filter that accepts IPv4 and IPv6
	// and does port/proto checks.

	_ = ipProto // retained for future tighter BPF filters

	const (
		BPF_LD  = 0x00
		BPF_JMP = 0x05
		BPF_RET = 0x06
		BPF_H   = 0x08
		BPF_ABS = 0x20
		BPF_JEQ = 0x10
		BPF_K   = 0x00
	)

	type sockFilter struct {
		Code uint16
		Jt   uint8
		Jf   uint8
		K    uint32
	}

	// Accept IPv4/IPv6; userspace filters UDP ports and native UET proto.
	// Keeps SRv6 outer encapsulation working without brittle BPF offsets.
	simple := []sockFilter{
		{Code: BPF_LD | BPF_H | BPF_ABS, K: 12},
		{Code: BPF_JMP | BPF_JEQ | BPF_K, Jt: 2, Jf: 0, K: 0x0800},
		{Code: BPF_JMP | BPF_JEQ | BPF_K, Jt: 1, Jf: 0, K: 0x86dd},
		{Code: BPF_RET | BPF_K, K: 0},
		{Code: BPF_RET | BPF_K, K: 0x40000},
	}

	type sockFprog struct {
		Len    uint16
		Filter *sockFilter
	}
	fprog := sockFprog{
		Len:    uint16(len(simple)),
		Filter: &simple[0],
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_SOCKET),
		uintptr(unix.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&fprog)),
		unsafe.Sizeof(fprog),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func splitLines(b []byte) []string {
	var lines []string
	start := 0
	for i, c := range b {
		if c == '\n' {
			lines = append(lines, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, string(b[start:]))
	}
	return lines
}

func fieldsWS(s string) []string {
	var out []string
	field := make([]byte, 0, 32)
	flush := func() {
		if len(field) > 0 {
			out = append(out, string(field))
			field = field[:0]
		}
	}
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			flush()
			continue
		}
		field = append(field, s[i])
	}
	flush()
	return out
}
