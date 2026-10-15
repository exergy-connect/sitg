//go:build linux

package link

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Endpoint holds resolved interface addressing.
type Endpoint struct {
	Iface   *net.Interface
	SrcMAC  net.HardwareAddr
	SrcIPv4 netip.Addr
	SrcIPv6 netip.Addr
	Index   int
}

// Socket is an AF_PACKET raw socket bound to an interface.
type Socket struct {
	fd int
	ep *Endpoint
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
