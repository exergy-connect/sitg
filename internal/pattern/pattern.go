package pattern

import (
	"net/netip"

	"github.com/jbemmel/sitg/internal/config"
)

// Selector chooses message sizes and destinations for each message.
type Selector struct {
	cfg   *config.Config
	peers []netip.Addr
	idx   int
}

func New(cfg *config.Config) *Selector {
	peers := append([]netip.Addr(nil), cfg.Peers...)
	if len(peers) == 0 && cfg.Dst.IsValid() {
		peers = []netip.Addr{cfg.Dst}
	}
	return &Selector{cfg: cfg, peers: peers}
}

// Next returns the destination and message size for the next message.
func (s *Selector) Next() (dst netip.Addr, msgSize int) {
	msgSize = s.cfg.MsgSize
	switch s.cfg.Pattern {
	case config.PatternMice:
		msgSize = s.cfg.PktSize
	case config.PatternElephant:
		if msgSize < 1024*1024 {
			msgSize = 4 * 1024 * 1024
		}
	case config.PatternP2P:
		// defaults
	case config.PatternOutcast:
		// round-robin destinations, one message each turn
	case config.PatternAllToAll:
		// same as outcast for a single sender; multi-peer fan-out
	}
	if len(s.peers) == 0 {
		return netip.Addr{}, msgSize
	}
	dst = s.peers[s.idx%len(s.peers)]
	s.idx++
	return dst, msgSize
}

func (s *Selector) Peers() []netip.Addr {
	return s.peers
}
