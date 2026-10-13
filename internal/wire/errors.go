package wire

import "errors"

var (
	ErrShortPacket   = errors.New("packet too short")
	ErrUnsupported   = errors.New("unsupported packet")
	ErrInvalidSRv6   = errors.New("invalid SRv6 destination")
	ErrBadChecksum   = errors.New("bad checksum")
	ErrUnknownProto  = errors.New("unknown protocol")
)
