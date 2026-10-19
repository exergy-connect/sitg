package wire

import (
	"encoding/binary"
	"hash/crc32"
)

const (
	UETPDSLen         = 12
	UETSESLen         = 44 // Standard Request
	UETSACKLen        = 32 // ACK_CC, including its 20-byte extension
	UETTypeData uint8 = 2  // RUD Request
	UETTypeSACK uint8 = 8  // ACK_CC
	UETModeRUD  uint8 = 0
)

// EncodeUETData emits a RUD Request with a Standard SES Write request.
// SITG uses preconfigured, symmetric 16-bit PDC IDs (no PDC negotiation).
// The CRC is reserved here and filled by BuildUETFrame once IP addresses exist.
func EncodeUETData(psn, qp, msgID, offset, length uint32, rtx bool, payload []byte, clearPSN ...uint32) []byte {
	b := make([]byte, UETPDSLen+UETSESLen+len(payload)+4)
	common := uint16(UETTypeData)<<11 | 3<<7 | 8 // Standard SES, ACK request
	if rtx {
		common |= 16
	}
	binary.BigEndian.PutUint16(b, common)
	// Default to the initial clear point; senders supply their acknowledged PSN.
	clear := ^uint32(0)
	if len(clearPSN) > 0 {
		clear = clearPSN[0]
	}
	delta := int32(clear - psn)
	if delta > 0 {
		delta = 0
	}
	if delta < -32768 {
		delta = -32768
	}
	binary.BigEndian.PutUint16(b[2:], uint16(int16(delta)))
	binary.BigEndian.PutUint32(b[4:], psn)
	binary.BigEndian.PutUint16(b[8:], uint16(qp))
	binary.BigEndian.PutUint16(b[10:], uint16(qp))
	s := b[12:]
	s[0] = 1 // Write
	if offset == 0 {
		s[1] |= 1
	}
	if uint64(offset)+uint64(len(payload)) >= uint64(length) {
		s[1] |= 2
	}
	binary.BigEndian.PutUint16(s[2:], uint16(msgID))
	binary.BigEndian.PutUint64(s[12:], uint64(offset))
	if offset != 0 {
		binary.BigEndian.PutUint32(s[32:], uint32(len(payload)))
		binary.BigEndian.PutUint32(s[36:], offset)
	}
	binary.BigEndian.PutUint32(s[40:], length)
	copy(b[UETPDSLen+UETSESLen:], payload)
	return b
}

// EncodeUETSACK translates the engine's exclusive cumulative ACK and base+1
// bitmap into an ACK_CC with a byte-aligned SACK base, per UET 1.0.1.
// Bits beyond this 64-bit aligned window remain pending for a subsequent ACK.
func EncodeUETSACK(qp, cumAck uint32, bitmap uint64) []byte {
	b := make([]byte, UETSACKLen+4)
	binary.BigEndian.PutUint16(b, uint16(UETTypeSACK)<<11)
	binary.BigEndian.PutUint32(b[4:], cumAck-1)
	binary.BigEndian.PutUint16(b[8:], uint16(qp))
	binary.BigEndian.PutUint16(b[10:], uint16(qp))
	base := cumAck &^ 7
	binary.BigEndian.PutUint16(b[14:], uint16(int16(int32(base-(cumAck-1)))))
	shift := cumAck - base
	bits := bitmap << (shift + 1)
	bits |= (uint64(1) << shift) - 1 // PSNs before CACK are already received
	binary.BigEndian.PutUint64(b[16:], bits)
	// CC type 0 = NSCC; idle congestion state is zero.
	return b
}

func DecodeUETTransport(b []byte) (*Frame, error) {
	if len(b) < UETPDSLen+4 {
		return nil, ErrShortPacket
	}
	common := binary.BigEndian.Uint16(b)
	f := &Frame{Proto: "uet", QP: uint32(binary.BigEndian.Uint16(b[8:]))}
	switch uint8(common >> 11) {
	case UETTypeData:
		if (common>>7)&15 != 3 {
			return nil, ErrUnsupported
		}
		if len(b) < UETPDSLen+UETSESLen+4 {
			return nil, ErrShortPacket
		}
		s := b[12:]
		if s[0]&63 != 1 {
			return nil, ErrUnsupported
		}
		f.Type = TypeData
		f.RTX = common&16 != 0
		f.PSN = binary.BigEndian.Uint32(b[4:])
		f.MsgID = uint32(binary.BigEndian.Uint16(s[2:]))
		f.Offset = uint32(binary.BigEndian.Uint64(s[12:]))
		f.Length = binary.BigEndian.Uint32(s[40:])
		f.Payload = append([]byte(nil), b[UETPDSLen+UETSESLen:len(b)-4]...)
	case UETTypeSACK:
		if len(b) < UETSACKLen+4 {
			return nil, ErrShortPacket
		}
		f.Type = TypeSACK
		f.CumAck = binary.BigEndian.Uint32(b[4:]) + 1
		base := f.CumAck - 1 + uint32(int32(int16(binary.BigEndian.Uint16(b[14:]))))
		bits := binary.BigEndian.Uint64(b[16:])
		for i := uint32(0); i < 64; i++ {
			delta := base + i - f.CumAck
			if bits&(uint64(1)<<i) != 0 && delta >= 1 && delta <= 64 {
				f.Bitmap |= uint64(1) << (delta - 1)
			}
		}
		f.PSN = f.CumAck
	default:
		return nil, ErrUnsupported
	}
	return f, nil
}

// BuildUETFrame fills the CRC32C over the innermost source IP address through
// the UET payload, including the zero UDP checksum or native entropy header.
func BuildUETFrame(opts BuildOpts, transport []byte) ([]byte, error) {
	frame, err := WrapEthernetIP(opts, transport, UETUDPPort, true)
	if err != nil {
		return nil, err
	}
	ip := EthernetHeaderLen
	if opts.UseSRv6 && !opts.NativeSRv6 {
		ip += IPv6HeaderLen
	}
	addr := ip + 8
	if opts.Encap == "udp4" || opts.Encap == "ip4" {
		addr = ip + 12
	}
	if len(transport) < 4 {
		return nil, ErrShortPacket
	}
	invariant := append([]byte(nil), frame[addr:len(frame)-4]...)
	if opts.NativeSRv6 {
		copy(invariant[16:32], opts.DstIP.AsSlice())
		if opts.Encap == "udp6" {
			invariant[IPv6HeaderLen-8+6], invariant[IPv6HeaderLen-8+7] = 0, 0
		}
	}
	crc := crc32.Checksum(invariant, crc32.MakeTable(crc32.Castagnoli))
	binary.BigEndian.PutUint32(frame[len(frame)-4:], crc)
	if opts.NativeSRv6 && opts.Encap == "udp6" {
		udp := frame[ip+IPv6HeaderLen:]
		udp[6], udp[7] = 0, 0
		binary.BigEndian.PutUint16(udp[6:8], UDPChecksumIPv6(opts.SrcIP, opts.DstIP, uint16(len(udp)), udp))
	}
	return frame, nil
}
