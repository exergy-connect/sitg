//go:build linux

package link

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestReserveUDP(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	s := &Socket{fd: -1}
	if err := s.ReserveUDP([]netip.Addr{ip}, []int{0}); err != nil {
		t.Fatal(err)
	}
	addr := s.udp[0].LocalAddr().(*net.UDPAddr)
	// A real UDP endpoint must own the port while AF_PACKET handles its copy.
	if conn, err := net.ListenUDP("udp4", addr); err == nil {
		conn.Close()
		t.Fatal("reserved port still bindable")
	}
	sender, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if _, err := sender.Write([]byte("uet")); err != nil {
		t.Fatal(err)
	}
	// Filtered datagrams must never enter the UDP receive queue.
	s.udp[0].SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err := s.udp[0].ReadFromUDP(make([]byte, 32)); err == nil {
		t.Fatal("drop filter queued a datagram")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatal(err)
	}
	// A bound, filtered socket must not generate an ICMP rejection either.
	sender.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err := sender.Read(make([]byte, 32)); err == nil {
		t.Fatal("unexpected UDP response")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatal("UDP rejected:", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatal("port not released:", err)
	}
	conn.Close()
}

func TestReserveUDPRollback(t *testing.T) {
	held, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	s := &Socket{fd: -1}
	if err := s.ReserveUDP([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, []int{0, held.LocalAddr().(*net.UDPAddr).Port}); err == nil {
		t.Fatal("expected port conflict")
	}
	if len(s.udp) != 0 {
		t.Fatal("failed reservation retained sockets")
	}
}
