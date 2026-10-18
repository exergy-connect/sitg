package wire

import (
	"encoding/binary"
	"hash/crc32"
)

const (
	MRCBTHLen            = 12
	MRCReqLen            = 20   // METH + per-packet RETH
	MRCSACKLen           = 48   // BTH + SETH + CC_STATE
	MRCOpcodeWrite uint8 = 0xca // RDMA WRITE Only
	MRCOpcodeSACK  uint8 = 0xdc
)

// EncodeMRCData implements OCP MRC 1.0 section 6.2.2. The demo uses
// preconfigured symmetric QPs and a zero-based synthetic memory region.
func EncodeMRCData(psn, qp, msgID, offset, length uint32, rtx bool, payload []byte) []byte {
	pad := (4 - len(payload)%4) % 4
	b := make([]byte, MRCBTHLen+MRCReqLen+len(payload)+pad+4)
	b[0] = MRCOpcodeWrite
	if offset == 0 && uint64(len(payload)) < uint64(length) {
		b[0] = 0xc6
	} else if offset > 0 {
		b[0] = 0xc7
		if uint64(offset)+uint64(len(payload)) >= uint64(length) {
			b[0] = 0xc8
		}
	}
	b[1] = byte(pad << 4)
	binary.BigEndian.PutUint16(b[2:], 0xffff)
	binary.BigEndian.PutUint32(b[4:], qp&0xffffff)
	binary.BigEndian.PutUint32(b[8:], psn&0xffffff)
	b[8] |= 0x80 // ACK request
	if rtx {
		b[8] |= 0x20
	}
	binary.BigEndian.PutUint16(b[14:], uint16(msgID))  // METH.MSN
	binary.BigEndian.PutUint64(b[16:], uint64(offset)) // RETH.VA
	binary.BigEndian.PutUint32(b[24:], 1)              // synthetic R_Key
	binary.BigEndian.PutUint32(b[28:], length)
	copy(b[32:], payload)
	return b
}

// EncodeMRCSACK translates SITG's exclusive ACK to MRC's inclusive CACK.
func EncodeMRCSACK(qp, cumAck uint32, bitmap uint64, entropy ...uint32) []byte {
	b := make([]byte, MRCSACKLen+4)
	b[0] = MRCOpcodeSACK
	binary.BigEndian.PutUint16(b[2:], 0xffff)
	binary.BigEndian.PutUint32(b[4:], qp&0xffffff)
	cack := (cumAck - 1) & 0xffffff
	binary.BigEndian.PutUint32(b[8:], cack)
	if len(entropy) > 0 {
		binary.BigEndian.PutUint32(b[16:], entropy[0])
	}
	binary.BigEndian.PutUint16(b[20:], uint16(qp))
	binary.BigEndian.PutUint16(b[22:], uint16(qp))
	binary.BigEndian.PutUint32(b[24:], cack)
	binary.BigEndian.PutUint16(b[30:], 2) // first selective bit = next expected + 1
	binary.BigEndian.PutUint64(b[32:], bitmap)
	return b
}

func DecodeMRCTransport(b []byte) (*Frame, error) {
	if len(b) < MRCBTHLen+4 {
		return nil, ErrShortPacket
	}
	if b[1]&15 != 0 {
		return nil, ErrUnsupported
	}
	f := &Frame{Proto: "mrc", QP: binary.BigEndian.Uint32(b[4:]) & 0xffffff, PSN: binary.BigEndian.Uint32(b[8:]) & 0xffffff}
	end := len(b) - 4
	switch b[0] {
	case 0xc6, 0xc7, 0xc8, 0xca:
		p := 16
		if b[8]&0x10 != 0 {
			p += 4
		}
		if end < p+16 {
			return nil, ErrShortPacket
		}
		f.Type = TypeData
		f.RTX = b[8]&0x20 != 0
		f.MsgID = uint32(binary.BigEndian.Uint16(b[14:]))
		f.Offset = uint32(binary.BigEndian.Uint64(b[p:]))
		f.Length = binary.BigEndian.Uint32(b[p+12:])
		p += 16
		end -= int(b[1] >> 4 & 3)
		if end < p {
			return nil, ErrShortPacket
		}
		f.Payload = append([]byte(nil), b[p:end]...)
	case 0xd8, 0xd9:
		if f.QP != 2 || f.PSN > 0xffff {
			return nil, ErrUnsupported
		}
		size, op := 16, byte(1)
		f.Type = TypeEVProbe
		if b[0] == 0xd9 {
			size, op = 36, 4
			f.Type = TypeEVProbeReply
		}
		if end < MRCBTHLen+size {
			return nil, ErrShortPacket
		}
		if b[13] != op {
			return nil, ErrUnsupported
		}
		f.ProbeID = uint16(f.PSN)
	case 0xdd:
		if end < 32 {
			return nil, ErrShortPacket
		}
		f.Type = TypeNACK
		f.ReflectedEV = binary.BigEndian.Uint32(b[16:])
		f.PSN = binary.BigEndian.Uint32(b[24:]) & 0xffffff
	case MRCOpcodeSACK:
		if end < MRCSACKLen {
			return nil, ErrShortPacket
		}
		cack := binary.BigEndian.Uint32(b[24:]) & 0xffffff
		f.Congestion = (b[13] >> 5) & 3
		f.AckPSN = (cack + uint32(int32(int16(binary.BigEndian.Uint16(b[14:]))))) & 0xffffff
		f.ReflectedEV = binary.BigEndian.Uint32(b[16:])
		f.Type = TypeSACK
		f.CumAck = (cack + 1) & 0xffffff
		base := (cack + uint32(int32(int16(binary.BigEndian.Uint16(b[30:]))))) & 0xffffff
		bits := binary.BigEndian.Uint64(b[32:])
		for i := uint32(0); i < 64; i++ {
			delta := (base + i - f.CumAck) & 0xffffff
			if bits&(uint64(1)<<i) != 0 && delta >= 1 && delta <= 64 {
				f.Bitmap |= uint64(1) << (delta - 1)
			}
		}
	default:
		return nil, ErrUnsupported
	}
	return f, nil
}

// BuildMRCFrame adds RoCE invariant CRC and a valid UDP checksum. No CRC
// validation is performed by the demo receiver.
func BuildMRCFrame(opts BuildOpts, transport []byte) ([]byte, error) {
	if opts.Encap != "udp4" && opts.Encap != "udp6" {
		return nil, ErrUnsupported
	}
	if len(transport) < MRCBTHLen+4 {
		return nil, ErrShortPacket
	}
	// MRC splits EV across source port (low 16) and flow label (high 16).
	// Current configured EV indices fit in 16 bits, so the high half is zero.
	zero := uint32(0)
	opts.FlowLabel = &zero
	frame, err := WrapEthernetIP(opts, transport, MRCUDPPort, false)
	if err != nil {
		return nil, err
	}
	ip := EthernetHeaderLen
	if opts.UseSRv6 {
		ip += IPv6HeaderLen
	}
	hdr := IPv6HeaderLen
	if opts.Encap == "udp4" {
		hdr = IPv4HeaderLen
	}
	udp := ip + hdr
	invariant := append([]byte(nil), frame[ip:len(frame)-4]...)
	if hdr == IPv4HeaderLen {
		invariant[1] = 0xff
		invariant[8] = 0xff
		invariant[10] = 0xff
		invariant[11] = 0xff
	} else {
		invariant[0] |= 0x0f
		invariant[1] = 0xff
		invariant[2] = 0xff
		invariant[3] = 0xff
		invariant[7] = 0xff
	}
	invariant[hdr+6] = 0xff
	invariant[hdr+7] = 0xff
	invariant[hdr+8+4] = 0xff // BTH reserved octet above destination QP
	crc := crc32.NewIEEE()
	crc.Write([]byte{255, 255, 255, 255, 255, 255, 255, 255})
	crc.Write(invariant)
	binary.LittleEndian.PutUint32(frame[len(frame)-4:], crc.Sum32())
	frame[udp+6] = 0
	frame[udp+7] = 0
	var csum uint16
	if hdr == IPv4HeaderLen {
		csum = UDPChecksumIPv4(opts.SrcIP, opts.DstIP, uint16(len(frame)-udp), frame[udp:])
	} else {
		csum = UDPChecksumIPv6(opts.SrcIP, opts.DstIP, uint16(len(frame)-udp), frame[udp:])
	}
	binary.BigEndian.PutUint16(frame[udp+6:], csum)
	return frame, nil
}

// EncodeMRCEVProbe implements OCP MRC 1.0 sections 7.4.7 and 7.5.6.
// Endpoint operations use QP 2 and echo the private 16-bit ID in BTH.PSN.
func EncodeMRCEVProbe(id uint16, reply bool) []byte {
	size, opcode, op := 16, byte(0xd8), byte(1)
	if reply {
		size, opcode, op = 36, 0xd9, 4
	}
	b := make([]byte, MRCBTHLen+size+4)
	b[0] = opcode
	binary.BigEndian.PutUint16(b[2:], 0xffff)
	binary.BigEndian.PutUint32(b[4:], 2)
	binary.BigEndian.PutUint32(b[8:], uint32(id))
	b[13] = op
	return b
}

// EncodeMRCSACKForPacket identifies the actual triggering packet independently
// of the cumulative PSN; EV feedback remains correct under out-of-order arrival.
func EncodeMRCSACKForPacket(qp, cumAck uint32, bitmap uint64, ev, psn uint32) []byte {
	b := EncodeMRCSACK(qp, cumAck, bitmap, ev)
	binary.BigEndian.PutUint16(b[14:], uint16(psn-((cumAck-1)&0xffffff)))
	return b
}
