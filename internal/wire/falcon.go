package wire

import "encoding/binary"

// Falcon v1.1 headers, sections 7.2, 7.5 and 7.7 of the OCP specification.
// SITG uses a cleartext UDP lab envelope rather than PSP/ESP security.
const (
	FalconUDPPort  = 4794 // SITG private convention, not an assigned Falcon port.
	FalconBaseLen  = 24
	FalconPushLen  = FalconBaseLen + 2
	FalconBACKLen  = 32
	FalconEACKLen  = FalconBACKLen + 16 + 16 + 8
	FalconPushData = 5
	FalconBACK     = 9
	FalconEACK     = 10
)

func falconHeader(buf []byte, qp uint32, kind byte) {
	binary.BigEndian.PutUint32(buf[:4], 0x10000000|(qp&0xffffff))
	buf[7] = kind << 1
}

// EncodeFalconData emits Push Data with an opaque lab ULP payload. Falcon has
// no message offset or retransmission flag; retransmissions retain their PSN.
func EncodeFalconData(psn, qp, msgID uint32, payload []byte) []byte {
	buf := make([]byte, FalconPushLen+len(payload))
	falconHeader(buf, qp, FalconPushData)
	buf[7] |= 2 << 5 // RDMA protocol type; ULP semantics are outside this lab subset.
	binary.BigEndian.PutUint32(buf[16:20], psn)
	binary.BigEndian.PutUint32(buf[20:24], msgID)
	binary.BigEndian.PutUint16(buf[24:26], uint16(len(payload)))
	copy(buf[26:], payload)
	return buf
}

// EncodeFalconSACK translates SITG's base+1 bitmap into Falcon's base-relative
// bitmap. Unused request-window and congestion metadata fields remain zero.
func EncodeFalconSACK(qp, cumAck uint32, bitmap uint64) []byte {
	buf := make([]byte, FalconEACKLen)
	falconHeader(buf, qp, FalconEACK)
	binary.BigEndian.PutUint32(buf[8:12], cumAck)
	for i := 0; i < 64; i++ {
		if bitmap&(uint64(1)<<i) != 0 {
			bit := i + 1
			buf[32+bit/8] |= 0x80 >> (bit % 8)
			buf[48+bit/8] |= 0x80 >> (bit % 8)
		}
	}
	return buf
}

func DecodeFalconTransport(payload []byte) (*Frame, error) {
	if len(payload) < 8 {
		return nil, ErrShortPacket
	}
	if payload[0]>>4 != 1 {
		return nil, ErrUnsupported
	}
	f := &Frame{Proto: "falcon", QP: binary.BigEndian.Uint32(payload[:4]) & 0xffffff}
	switch (payload[7] >> 1) & 15 {
	case FalconPushData:
		if len(payload) < FalconPushLen {
			return nil, ErrShortPacket
		}
		if payload[7]>>5 != 2 {
			return nil, ErrUnsupported
		}
		n := int(binary.BigEndian.Uint16(payload[24:26]))
		if len(payload) < FalconPushLen+n {
			return nil, ErrShortPacket
		}
		f.Type = TypeData
		f.PSN = binary.BigEndian.Uint32(payload[16:20])
		f.MsgID = binary.BigEndian.Uint32(payload[20:24])
		f.Length = uint32(n)
		f.Payload = append([]byte(nil), payload[26:26+n]...)
	case FalconBACK, FalconEACK:
		kind := (payload[7] >> 1) & 15
		need := FalconBACKLen
		if kind == FalconEACK {
			need = FalconEACKLen
		}
		if len(payload) < need {
			return nil, ErrShortPacket
		}
		f.Type = TypeSACK
		f.CumAck = binary.BigEndian.Uint32(payload[8:12])
		f.PSN = f.CumAck
		if kind == FalconEACK {
			for i := 0; i < 64; i++ {
				bit := i + 1
				if payload[32+bit/8]&(0x80>>(bit%8)) != 0 {
					f.Bitmap |= uint64(1) << i
				}
			}
		}
	default:
		return nil, ErrUnsupported
	}
	return f, nil
}

func BuildFalconFrame(opts BuildOpts, transport []byte) ([]byte, error) {
	if opts.Encap != "udp4" && opts.Encap != "udp6" {
		return nil, ErrUnsupported
	}
	return WrapEthernetIP(opts, transport, FalconUDPPort, false)
}
