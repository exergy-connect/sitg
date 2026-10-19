package wire

import (
	"encoding/binary"
	"net"
	"net/netip"
)

const (
	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86DD

	IPProtoICMP  = 1
	IPProtoIPv4  = 4
	IPProtoTCP   = 6
	IPProtoUDP   = 17
	IPProtoIPv6  = 41
	IPProtoICMP6 = 58

	UETUDPPort = 4793
	MRCUDPPort = 4791

	EthernetHeaderLen = 14
	IPv4HeaderLen     = 20
	IPv6HeaderLen     = 40
	UDPHeaderLen      = 8
	EntropyHeaderLen  = 4
)

// PacketType distinguishes data from SACK control.
type PacketType uint8

const (
	TypeData         PacketType = 0
	TypeSACK         PacketType = 1
	TypeEVProbe      PacketType = 2
	TypeEVProbeReply PacketType = 3
	TypeNACK         PacketType = 4
)

// Frame is a decoded transport packet.
type Frame struct {
	Type        PacketType
	Proto       string // "uet", "mrc", or "falcon"
	Encap       string
	SrcIP       netip.Addr
	DstIP       netip.Addr
	SrcMAC      net.HardwareAddr
	DstMAC      net.HardwareAddr
	Entropy     uint16
	MRCEV       uint32 // complete routing EV from this packet header
	AckPSN      uint32
	Congestion  uint8
	ReflectedEV uint32 // forward EV in SETH; independent of the ACK routing EV
	ProbeID     uint16
	PSN         uint32
	QP          uint32
	MsgID       uint32
	Offset      uint32
	Length      uint32
	RTX         bool
	CumAck      uint32
	Bitmap      uint64
	Payload     []byte
	OuterSRv6   bool
	OuterDst    netip.Addr
}

// BuildOpts controls Ethernet/IP/UDP/SRv6 framing.
type BuildOpts struct {
	SrcMAC     net.HardwareAddr
	DstMAC     net.HardwareAddr
	SrcIP      netip.Addr
	DstIP      netip.Addr
	Encap      string // udp6|udp4|ip6|ip4
	IPProto    uint8  // for native UET
	Entropy    uint16
	FlowLabel  *uint32 // nil uses the protocol default
	UseSRv6    bool
	NativeSRv6 bool // one IPv6 header; DstIP is the terminal checksum destination
	SRv6Dst    netip.Addr
	SRv6SrcIP  netip.Addr // outer IPv6 source when UseSRv6 (required for IPv4 inner)
	TOS        uint8
	HopLimit   uint8
}

func checksumFold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func sumBytes(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

// UDPChecksumIPv6 computes the IPv6 UDP checksum. A zero result becomes 0xffff.
func UDPChecksumIPv6(src, dst netip.Addr, udpLen uint16, udpAndPayload []byte) uint16 {
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], src.AsSlice())
	copy(pseudo[16:32], dst.AsSlice())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(udpLen))
	pseudo[39] = IPProtoUDP
	sum := sumBytes(pseudo) + sumBytes(udpAndPayload)
	csum := checksumFold(sum)
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

// UDPChecksumIPv4 computes the IPv4 UDP checksum.
func UDPChecksumIPv4(src, dst netip.Addr, udpLen uint16, udpAndPayload []byte) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src.AsSlice())
	copy(pseudo[4:8], dst.AsSlice())
	pseudo[9] = IPProtoUDP
	binary.BigEndian.PutUint16(pseudo[10:12], udpLen)
	sum := sumBytes(pseudo) + sumBytes(udpAndPayload)
	csum := checksumFold(sum)
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

func IPv4Checksum(hdr []byte) uint16 {
	return checksumFold(sumBytes(hdr))
}

func writeEthernet(buf []byte, dst, src net.HardwareAddr, etherType uint16) int {
	copy(buf[0:6], dst)
	copy(buf[6:12], src)
	binary.BigEndian.PutUint16(buf[12:14], etherType)
	return EthernetHeaderLen
}

func writeIPv4(buf []byte, src, dst netip.Addr, totalLen int, proto uint8, tos uint8, ttl uint8, id uint16) int {
	buf[0] = 0x45
	buf[1] = tos
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[4:6], id)
	binary.BigEndian.PutUint16(buf[6:8], 0x4000) // DF
	buf[8] = ttl
	buf[9] = proto
	buf[10], buf[11] = 0, 0
	copy(buf[12:16], src.AsSlice())
	copy(buf[16:20], dst.AsSlice())
	csum := IPv4Checksum(buf[:IPv4HeaderLen])
	binary.BigEndian.PutUint16(buf[10:12], csum)
	return IPv4HeaderLen
}

func writeIPv6(buf []byte, src, dst netip.Addr, payloadLen int, nextHeader uint8, hopLimit uint8, flowLabel uint32) int {
	// version=6, traffic class=0, flow label
	vtf := uint32(6<<28) | (flowLabel & 0xfffff)
	binary.BigEndian.PutUint32(buf[0:4], vtf)
	binary.BigEndian.PutUint16(buf[4:6], uint16(payloadLen))
	buf[6] = nextHeader
	buf[7] = hopLimit
	copy(buf[8:24], src.AsSlice())
	copy(buf[24:40], dst.AsSlice())
	return IPv6HeaderLen
}

func writeUDP(buf []byte, srcPort, dstPort uint16, length uint16) int {
	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint16(buf[4:6], length)
	binary.BigEndian.PutUint16(buf[6:8], 0) // checksum filled later
	return UDPHeaderLen
}

func writeEntropyHeader(buf []byte, entropy uint16) int {
	binary.BigEndian.PutUint16(buf[0:2], entropy)
	binary.BigEndian.PutUint16(buf[2:4], 0)
	return EntropyHeaderLen
}

// WrapEthernetIP builds Ethernet/IP framing with optional encapsulated or native SRv6.
// Native SRv6 writes SRv6Dst into the header and uses terminal DstIP for checksums.
func WrapEthernetIP(opts BuildOpts, transportPayload []byte, udpDstPort uint16, zeroUDPChecksum bool) ([]byte, error) {
	if opts.NativeSRv6 && (!opts.UseSRv6 || !opts.DstIP.Is6() || opts.DstIP.Is4In6() || !opts.SrcIP.Is6() || opts.SrcIP.Is4In6() || (opts.Encap != "udp6" && opts.Encap != "ip6") || !opts.SRv6Dst.Is6() || opts.SRv6Dst.Is4In6()) {
		return nil, ErrInvalidSRv6
	}
	ipv4 := opts.Encap == "udp4" || opts.Encap == "ip4"
	useUDP := opts.Encap == "udp4" || opts.Encap == "udp6"
	hopLimit := opts.HopLimit
	if hopLimit == 0 {
		hopLimit = 64
	}

	flowLabel := uint32(opts.Entropy)
	if opts.FlowLabel != nil {
		flowLabel = *opts.FlowLabel
	}
	var inner []byte
	if useUDP {
		udpLen := UDPHeaderLen + len(transportPayload)
		inner = make([]byte, udpLen)
		writeUDP(inner, opts.Entropy, udpDstPort, uint16(udpLen))
		copy(inner[UDPHeaderLen:], transportPayload)
		if !zeroUDPChecksum || opts.NativeSRv6 {
			var csum uint16
			if ipv4 {
				csum = UDPChecksumIPv4(opts.SrcIP, opts.DstIP, uint16(udpLen), inner)
			} else {
				csum = UDPChecksumIPv6(opts.SrcIP, opts.DstIP, uint16(udpLen), inner)
			}
			binary.BigEndian.PutUint16(inner[6:8], csum)
		}
	} else {
		inner = make([]byte, EntropyHeaderLen+len(transportPayload))
		writeEntropyHeader(inner, opts.Entropy)
		copy(inner[EntropyHeaderLen:], transportPayload)
	}

	var ipPkt []byte
	if ipv4 {
		total := IPv4HeaderLen + len(inner)
		ipPkt = make([]byte, total)
		proto := uint8(IPProtoUDP)
		if !useUDP {
			proto = opts.IPProto
		}
		writeIPv4(ipPkt, opts.SrcIP, opts.DstIP, total, proto, opts.TOS, hopLimit, opts.Entropy)
		copy(ipPkt[IPv4HeaderLen:], inner)
	} else {
		ipPkt = make([]byte, IPv6HeaderLen+len(inner))
		next := uint8(IPProtoUDP)
		if !useUDP {
			next = opts.IPProto
		}
		dst := opts.DstIP
		if opts.NativeSRv6 {
			dst = opts.SRv6Dst
		}
		writeIPv6(ipPkt, opts.SrcIP, dst, len(inner), next, hopLimit, flowLabel)
		copy(ipPkt[IPv6HeaderLen:], inner)
	}

	if opts.UseSRv6 && !opts.NativeSRv6 {
		if !opts.SRv6Dst.IsValid() || !opts.SRv6Dst.Is6() {
			return nil, ErrInvalidSRv6
		}
		outerSrc := opts.SRv6SrcIP
		if !outerSrc.IsValid() {
			outerSrc = opts.SrcIP
		}
		if !outerSrc.Is6() {
			return nil, ErrInvalidSRv6
		}
		innerNH := uint8(IPProtoIPv6)
		if ipv4 {
			innerNH = IPProtoIPv4
		}
		outer := make([]byte, IPv6HeaderLen+len(ipPkt))
		writeIPv6(outer, outerSrc, opts.SRv6Dst, len(ipPkt), innerNH, hopLimit, flowLabel)
		copy(outer[IPv6HeaderLen:], ipPkt)
		ipPkt = outer
		ipv4 = false
	}

	etherType := uint16(EtherTypeIPv6)
	if ipv4 && !opts.UseSRv6 {
		etherType = EtherTypeIPv4
	}
	frame := make([]byte, EthernetHeaderLen+len(ipPkt))
	writeEthernet(frame, opts.DstMAC, opts.SrcMAC, etherType)
	copy(frame[EthernetHeaderLen:], ipPkt)
	return frame, nil
}
