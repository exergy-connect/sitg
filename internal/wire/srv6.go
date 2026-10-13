package wire

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// PathParams configures algorithmic uSID path generation.
type PathParams struct {
	Locator  netip.Addr
	Paths    int
	Hops     int
	Radix    int
	USIDBase uint16
}

// EncodeUSID builds a uN-style SRv6 destination for path index i.
// Layout: 32-bit locator | up to 6 × 16-bit uSIDs | zero padding.
func EncodeUSID(p PathParams, pathIndex int) (netip.Addr, error) {
	if !p.Locator.IsValid() || !p.Locator.Is6() {
		return netip.Addr{}, ErrInvalidSRv6
	}
	if p.Hops < 1 || p.Hops > 6 {
		return netip.Addr{}, fmt.Errorf("hops must be 1..6")
	}
	if p.Radix < 2 {
		return netip.Addr{}, fmt.Errorf("radix must be >= 2")
	}
	if p.Paths < 1 {
		return netip.Addr{}, fmt.Errorf("paths must be >= 1")
	}
	if pathIndex < 0 || pathIndex >= p.Paths {
		return netip.Addr{}, fmt.Errorf("path index out of range")
	}

	var addr [16]byte
	loc := p.Locator.As16()
	copy(addr[0:4], loc[0:4])

	i := pathIndex
	for k := 0; k < p.Hops; k++ {
		hop := p.USIDBase + uint16(i%p.Radix)
		i /= p.Radix
		off := 4 + k*2
		binary.BigEndian.PutUint16(addr[off:off+2], hop)
	}
	return netip.AddrFrom16(addr), nil
}

// DecodeUSIDHops extracts the ordered uSID hop list from a destination address.
func DecodeUSIDHops(dst netip.Addr, hops int) ([]uint16, [4]byte, error) {
	if !dst.IsValid() || !dst.Is6() {
		return nil, [4]byte{}, ErrInvalidSRv6
	}
	if hops < 1 || hops > 6 {
		return nil, [4]byte{}, fmt.Errorf("hops must be 1..6")
	}
	b := dst.As16()
	var loc [4]byte
	copy(loc[:], b[0:4])
	out := make([]uint16, hops)
	for k := 0; k < hops; k++ {
		off := 4 + k*2
		out[k] = binary.BigEndian.Uint16(b[off : off+2])
	}
	return out, loc, nil
}

// AllPaths generates all path destinations for the given parameters.
func AllPaths(p PathParams) ([]netip.Addr, error) {
	out := make([]netip.Addr, p.Paths)
	for i := 0; i < p.Paths; i++ {
		addr, err := EncodeUSID(p, i)
		if err != nil {
			return nil, err
		}
		out[i] = addr
	}
	return out, nil
}
