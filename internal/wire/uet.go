package wire

import (
	"encoding/binary"
)

const (
	UETPDSLen = 12
	UETSESLen = 20
	UETSACKLen = UETPDSLen + 12 // PDS + cumAck + bitmap

	UETTypeData uint8 = 0
	UETTypeSACK uint8 = 1

	UETModeRUD uint8 = 0
)

// EncodeUETData builds the UET transport payload (PDS + SES + data).
func EncodeUETData(psn, qp, msgID, offset, length uint32, rtx bool, payload []byte) []byte {
	buf := make([]byte, UETPDSLen+UETSESLen+len(payload))
	// PDS: type(1) | mode(1) | flags(1) | rsvd(1) | psn(4) | qp(4)
	buf[0] = UETTypeData
	buf[1] = UETModeRUD
	if rtx {
		buf[2] = 0x01
	}
	binary.BigEndian.PutUint32(buf[4:8], psn)
	binary.BigEndian.PutUint32(buf[8:12], qp)
	// SES: msgID(4) | offset(4) | length(4) | rsvd(8)
	binary.BigEndian.PutUint32(buf[12:16], msgID)
	binary.BigEndian.PutUint32(buf[16:20], offset)
	binary.BigEndian.PutUint32(buf[20:24], length)
	copy(buf[UETPDSLen+UETSESLen:], payload)
	return buf
}

// EncodeUETSACK builds a UET SACK transport payload.
func EncodeUETSACK(qp, cumAck uint32, bitmap uint64) []byte {
	buf := make([]byte, UETSACKLen)
	buf[0] = UETTypeSACK
	buf[1] = UETModeRUD
	binary.BigEndian.PutUint32(buf[4:8], cumAck)
	binary.BigEndian.PutUint32(buf[8:12], qp)
	binary.BigEndian.PutUint32(buf[12:16], cumAck)
	binary.BigEndian.PutUint64(buf[16:24], bitmap)
	return buf
}

// DecodeUETTransport parses PDS(+SES or SACK) from transport payload.
func DecodeUETTransport(payload []byte) (*Frame, error) {
	if len(payload) < UETPDSLen {
		return nil, ErrShortPacket
	}
	f := &Frame{Proto: "uet"}
	switch payload[0] {
	case UETTypeData:
		if len(payload) < UETPDSLen+UETSESLen {
			return nil, ErrShortPacket
		}
		f.Type = TypeData
		f.RTX = payload[2]&0x01 != 0
		f.PSN = binary.BigEndian.Uint32(payload[4:8])
		f.QP = binary.BigEndian.Uint32(payload[8:12])
		f.MsgID = binary.BigEndian.Uint32(payload[12:16])
		f.Offset = binary.BigEndian.Uint32(payload[16:20])
		f.Length = binary.BigEndian.Uint32(payload[20:24])
		f.Payload = append([]byte(nil), payload[UETPDSLen+UETSESLen:]...)
	case UETTypeSACK:
		if len(payload) < UETSACKLen {
			return nil, ErrShortPacket
		}
		f.Type = TypeSACK
		f.CumAck = binary.BigEndian.Uint32(payload[12:16])
		f.QP = binary.BigEndian.Uint32(payload[8:12])
		f.Bitmap = binary.BigEndian.Uint64(payload[16:24])
		f.PSN = f.CumAck
	default:
		return nil, ErrUnsupported
	}
	return f, nil
}

// BuildUETFrame builds a complete Ethernet frame for UET.
func BuildUETFrame(opts BuildOpts, transport []byte) ([]byte, error) {
	return WrapEthernetIP(opts, transport, UETUDPPort, true)
}
