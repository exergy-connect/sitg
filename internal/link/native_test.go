//go:build linux

package link

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func TestReserveNative(t *testing.T) {
	for _, tc := range []struct{ network, address string }{{"ip4:253", "127.0.0.1"}, {"ip6:253", "::1"}} {
		t.Run(tc.network, func(t *testing.T) {
			s := &Socket{fd: -1}
			defer s.Close()
			if err := s.ReserveNative([]netip.Addr{netip.MustParseAddr(tc.address)}, 253); err != nil {
				if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
					t.Skip("requires CAP_NET_RAW")
				}
				t.Fatal(err)
			}
			receiver := s.native[0]
			sender, err := net.DialIP(tc.network, nil, &net.IPAddr{IP: net.ParseIP(tc.address)})
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			if _, err := sender.Write([]byte("native UET")); err != nil {
				t.Fatal(err)
			}
			receiver.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
			if _, _, err := receiver.ReadFrom(make([]byte, 128)); err == nil {
				t.Fatal("drop filter queued native packet")
			} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := receiver.ReadFrom(make([]byte, 128)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("raw socket not closed: %v", err)
			}
		})
	}
}
