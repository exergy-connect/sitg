//go:build !linux

package link

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

type Endpoint struct {
	Iface   *net.Interface
	SrcMAC  net.HardwareAddr
	SrcIPv4 netip.Addr
	SrcIPv6 netip.Addr
	Index   int
}

type Socket struct {
	ep *Endpoint
}

func ResolveEndpoint(ifaceName string) (*Endpoint, error) {
	return nil, fmt.Errorf("sitg link support requires linux")
}

func OpenSocket(ep *Endpoint, ipProto uint8) (*Socket, error) {
	return nil, fmt.Errorf("sitg link support requires linux")
}

func (s *Socket) Endpoint() *Endpoint             { return s.ep }
func (s *Socket) Close() error                    { return nil }
func (s *Socket) Send(frame []byte) error         { return fmt.Errorf("unsupported") }
func (s *Socket) Recv(buf []byte) (int, error)    { return 0, fmt.Errorf("unsupported") }
func (s *Socket) SetNonblock(nonblock bool) error { return nil }
func (s *Socket) FD() int                         { return -1 }

func ResolveDestinationMAC(ep *Endpoint, ip netip.Addr, timeout time.Duration) (net.HardwareAddr, error) {
	return nil, fmt.Errorf("unsupported")
}
