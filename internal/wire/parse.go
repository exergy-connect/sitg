package wire

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// ParseEthernetFrame decodes a raw Ethernet frame into a transport Frame.
// ipProto is the expected native UET IP protocol number.
func ParseEthernetFrame(raw []byte, ipProto uint8) (*Frame, error) {
	if len(raw) < EthernetHeaderLen {
		return nil, ErrShortPacket
	}
	dstMAC := append(net.HardwareAddr(nil), raw[0:6]...)
	srcMAC := append(net.HardwareAddr(nil), raw[6:12]...)
	etherType := binary.BigEndian.Uint16(raw[12:14])
	payload := raw[EthernetHeaderLen:]

	switch etherType {
	case EtherTypeIPv4:
		return parseIP(payload, false, ipProto, dstMAC, srcMAC, false, netip.Addr{})
	case EtherTypeIPv6:
		return parseIPv6MaybeSRv6(payload, ipProto, dstMAC, srcMAC)
	default:
		return nil, ErrUnsupported
	}
}

func parseIPv6MaybeSRv6(payload []byte, ipProto uint8, dstMAC, srcMAC net.HardwareAddr) (*Frame, error) {
	if len(payload) < IPv6HeaderLen {
		return nil, ErrShortPacket
	}
	next := payload[6]
	dstIP, _ := netip.AddrFromSlice(payload[24:40])
	inner := payload[IPv6HeaderLen:]

	switch next {
	case IPProtoIPv6:
		f, err := parseIP(inner, true, ipProto, dstMAC, srcMAC, true, dstIP)
		if err != nil {
			return nil, err
		}
		return f, nil
	case IPProtoIPv4:
		f, err := parseIP(inner, false, ipProto, dstMAC, srcMAC, true, dstIP)
		if err != nil {
			return nil, err
		}
		return f, nil
	default:
		return parseIP(payload, true, ipProto, dstMAC, srcMAC, false, netip.Addr{})
	}
}

func parseIP(payload []byte, isIPv6 bool, ipProto uint8, dstMAC, srcMAC net.HardwareAddr, outerSRv6 bool, outerDst netip.Addr) (*Frame, error) {
	var (
		srcIP, dstIP netip.Addr
		next         uint8
		body         []byte
	)

	if isIPv6 {
		if len(payload) < IPv6HeaderLen {
			return nil, ErrShortPacket
		}
		next = payload[6]
		srcIP, _ = netip.AddrFromSlice(payload[8:24])
		dstIP, _ = netip.AddrFromSlice(payload[24:40])
		body = payload[IPv6HeaderLen:]
	} else {
		if len(payload) < IPv4HeaderLen {
			return nil, ErrShortPacket
		}
		ihl := int(payload[0]&0x0f) * 4
		if ihl < IPv4HeaderLen || len(payload) < ihl {
			return nil, ErrShortPacket
		}
		next = payload[9]
		srcIP, _ = netip.AddrFromSlice(payload[12:16])
		dstIP, _ = netip.AddrFromSlice(payload[16:20])
		body = payload[ihl:]
	}

	var (
		entropy uint16
		encap   string
		trans   []byte
	)

	switch next {
	case IPProtoUDP:
		if len(body) < UDPHeaderLen {
			return nil, ErrShortPacket
		}
		srcPort := binary.BigEndian.Uint16(body[0:2])
		dstPort := binary.BigEndian.Uint16(body[2:4])
		entropy = srcPort
		trans = body[UDPHeaderLen:]
		if isIPv6 {
			encap = "udp6"
		} else {
			encap = "udp4"
		}
		f, err := decodeTransport(dstPort, trans)
		if err != nil {
			return nil, err
		}
		f.SrcIP = srcIP
		f.DstIP = dstIP
		f.SrcMAC = srcMAC
		f.DstMAC = dstMAC
		f.Entropy = entropy
		f.Encap = encap
		f.OuterSRv6 = outerSRv6
		f.OuterDst = outerDst
		return f, nil
	default:
		if next != ipProto {
			return nil, ErrUnsupported
		}
		if len(body) < EntropyHeaderLen {
			return nil, ErrShortPacket
		}
		entropy = binary.BigEndian.Uint16(body[0:2])
		trans = body[EntropyHeaderLen:]
		if isIPv6 {
			encap = "ip6"
		} else {
			encap = "ip4"
		}
		f, err := DecodeUETTransport(trans)
		if err != nil {
			return nil, err
		}
		f.SrcIP = srcIP
		f.DstIP = dstIP
		f.SrcMAC = srcMAC
		f.DstMAC = dstMAC
		f.Entropy = entropy
		f.Encap = encap
		f.OuterSRv6 = outerSRv6
		f.OuterDst = outerDst
		return f, nil
	}
}

func decodeTransport(dstPort uint16, trans []byte) (*Frame, error) {
	switch dstPort {
	case UETUDPPort:
		return DecodeUETTransport(trans)
	case FalconUDPPort:
		return DecodeFalconTransport(trans)
	case MRCUDPPort:
		return DecodeMRCTransport(trans)
	default:
		return nil, ErrUnknownProto
	}
}
