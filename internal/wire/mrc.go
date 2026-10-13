package wire

import (
	"encoding/binary"
)

const (
	MRCBTHLen = 12
	MRCReqLen = 8
	MRCSACKLen = MRCBTHLen + 12

	MRCOpcodeWrite uint8 = 0x50 // transport prefix 0101 + write
	MRCOpcodeSACK  uint8 = 0x51
)

// EncodeMRCData builds MRC transport payload (BTH + request + data).
func EncodeMRCData(psn, qp, msgID, offset, length uint32, rtx bool, payload []byte) []byte {
	buf := make([]byte, MRCBTHLen+MRCReqLen+len(payload))
	// BTH: opcode(1) | flags(1) | pkey(2) | dqpn(4) | psn(4)
	// flags: bit0 = rtx, bit7 always set to mark MRC (tsh-like)
	buf[0] = MRCOpcodeWrite
	if rtx {
		buf[1] = 0x01
	}
	binary.BigEndian.PutUint16(buf[2:4], 0xffff) // pkey
	binary.BigEndian.PutUint32(buf[4:8], qp&0xffffff)
	binary.BigEndian.PutUint32(buf[8:12], psn&0xffffff)
	// Request header: msgID(2) | offset(2) | length(4) compacted
	binary.BigEndian.PutUint16(buf[12:14], uint16(msgID))
	binary.BigEndian.PutUint16(buf[14:16], uint16(offset))
	binary.BigEndian.PutUint32(buf[16:20], length)
	copy(buf[MRCBTHLen+MRCReqLen:], payload)
	return buf
}

// EncodeMRCSACK builds an MRC SACK transport payload.
func EncodeMRCSACK(qp, cumAck uint32, bitmap uint64) []byte {
	buf := make([]byte, MRCSACKLen)
	buf[0] = MRCOpcodeSACK
	binary.BigEndian.PutUint16(buf[2:4], 0xffff)
	binary.BigEndian.PutUint32(buf[4:8], qp&0xffffff)
	binary.BigEndian.PutUint32(buf[8:12], cumAck&0xffffff)
	binary.BigEndian.PutUint32(buf[12:16], cumAck)
	binary.BigEndian.PutUint64(buf[16:24], bitmap)
	return buf
}

// DecodeMRCTransport parses BTH(+request or SACK) from transport payload.
func DecodeMRCTransport(payload []byte) (*Frame, error) {
	if len(payload) < MRCBTHLen {
		return nil, ErrShortPacket
	}
	f := &Frame{Proto: "mrc"}
	opcode := payload[0]
	switch opcode {
	case MRCOpcodeWrite:
		if len(payload) < MRCBTHLen+MRCReqLen {
			return nil, ErrShortPacket
		}
		f.Type = TypeData
		f.RTX = payload[1]&0x01 != 0
		f.QP = binary.BigEndian.Uint32(payload[4:8]) & 0xffffff
		f.PSN = binary.BigEndian.Uint32(payload[8:12]) & 0xffffff
		f.MsgID = uint32(binary.BigEndian.Uint16(payload[12:14]))
		f.Offset = uint32(binary.BigEndian.Uint16(payload[14:16]))
		f.Length = binary.BigEndian.Uint32(payload[16:20])
		f.Payload = append([]byte(nil), payload[MRCBTHLen+MRCReqLen:]...)
	case MRCOpcodeSACK:
		if len(payload) < MRCSACKLen {
			return nil, ErrShortPacket
		}
		f.Type = TypeSACK
		f.QP = binary.BigEndian.Uint32(payload[4:8]) & 0xffffff
		f.CumAck = binary.BigEndian.Uint32(payload[12:16])
		f.Bitmap = binary.BigEndian.Uint64(payload[16:24])
		f.PSN = f.CumAck
	default:
		return nil, ErrUnsupported
	}
	return f, nil
}

// BuildMRCFrame builds a complete Ethernet frame for MRC.
func BuildMRCFrame(opts BuildOpts, transport []byte) ([]byte, error) {
	if opts.Encap != "udp4" && opts.Encap != "udp6" {
		return nil, ErrUnsupported
	}
	return WrapEthernetIP(opts, transport, MRCUDPPort, false)
}
