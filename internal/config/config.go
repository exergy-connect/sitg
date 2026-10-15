package config

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type Role string

const (
	RoleSend Role = "send"
	RoleRecv Role = "recv"
)

type Proto string

const (
	ProtoUET    Proto = "uet"
	ProtoMRC    Proto = "mrc"
	ProtoFalcon Proto = "falcon"
	ProtoAll    Proto = "all"
)

type Encap string

const (
	EncapAll  Encap = "all"
	EncapUDP6 Encap = "udp6"
	EncapUDP4 Encap = "udp4"
	EncapIP6  Encap = "ip6"
	EncapIP4  Encap = "ip4"
)

type EntropyMode string

const (
	EntropyECMP EntropyMode = "ecmp"
	EntropySRv6 EntropyMode = "srv6"
)

type Pattern string

const (
	PatternP2P      Pattern = "p2p"
	PatternElephant Pattern = "elephant"
	PatternMice     Pattern = "mice"
	PatternOutcast  Pattern = "outcast"
	PatternAllToAll Pattern = "alltoall"
)

// Config holds all CLI parameters for a sitg session.
type Config struct {
	Role           Role
	Iface          string
	Proto          Proto
	Encap          Encap
	IPProto        uint8
	Dst            netip.Addr
	DstMAC         net.HardwareAddr
	Pattern        Pattern
	Peers          []netip.Addr
	MsgSize        int
	PktSize        int
	RateBps        uint64
	Duration       time.Duration
	Window         int
	SackEvery      int
	RTO            time.Duration
	Entropy        EntropyMode
	Locator        netip.Addr
	Paths          int
	Hops           int
	Radix          int
	USIDBase       uint16
	QP             uint32
	FalconCMPort   int
	ConnectTimeout time.Duration
}

func Parse(args []string) (*Config, error) {
	fs := flag.NewFlagSet("sitg", flag.ContinueOnError)

	role := fs.String("role", "send", "role: send|recv")
	iface := fs.String("iface", "", "network interface (required)")
	cmPort := fs.Int("falcon-cm-port", 4795, "TCP port for SITG Falcon connection management")
	connectTimeout := fs.Duration("connect-timeout", 5*time.Second, "Falcon setup and drain timeout")
	proto := fs.String("proto", "uet", "protocol: uet|mrc|falcon|all (all: receiver only)")
	encap := fs.String("encap", "udp6", "encapsulation: udp6|udp4|ip6|ip4|all (all: receiver only)")
	ipProto := fs.Int("ip-proto", 253, "IP protocol / next-header for native UET")
	dst := fs.String("dst", "", "destination IP address")
	dstMAC := fs.String("dst-mac", "", "destination MAC (optional if neighbor known)")
	pattern := fs.String("pattern", "p2p", "pattern: p2p|elephant|mice|outcast|alltoall")
	peers := fs.String("peers", "", "comma-separated peer IPs for outcast/alltoall")
	msgSize := fs.String("msg-size", "32KiB", "message size")
	pktSize := fs.String("pkt-size", "4096", "payload bytes per packet")
	rate := fs.String("rate", "10Gbps", "send rate")
	duration := fs.Duration("duration", 10*time.Second, "run duration")
	window := fs.Int("window", 256, "in-flight packet window")
	sackEvery := fs.Int("sack-every", 16, "receiver emits SACK every N data packets")
	rto := fs.Duration("rto", time.Millisecond, "retransmission timeout")
	entropy := fs.String("entropy", "ecmp", "entropy mode: ecmp|srv6")
	locator := fs.String("locator", "fc00::", "SRv6 locator prefix (32-bit)")
	paths := fs.Int("paths", 64, "number of SRv6 paths / entropy values")
	hops := fs.Int("hops", 3, "uSID hops per path (max 6)")
	radix := fs.Int("radix", 32, "fabric radix for path encoding")
	usidBase := fs.String("usid-base", "0x0100", "base 16-bit uSID value")
	qp := fs.Uint("qp", 1, "queue pair / PDC identifier")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// All protocols implies all encapsulations unless explicitly restricted.
	if Proto(*proto) == ProtoAll {
		explicit := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "encap" {
				explicit = true
			}
		})
		if !explicit {
			*encap = string(EncapAll)
		}
	}
	cfg := &Config{
		Role:           Role(*role),
		Iface:          *iface,
		Proto:          Proto(*proto),
		FalconCMPort:   *cmPort,
		ConnectTimeout: *connectTimeout,
		Encap:          Encap(*encap),
		IPProto:        uint8(*ipProto),
		Pattern:        Pattern(*pattern),
		Window:         *window,
		SackEvery:      *sackEvery,
		RTO:            *rto,
		Entropy:        EntropyMode(*entropy),
		Paths:          *paths,
		Hops:           *hops,
		Radix:          *radix,
		QP:             uint32(*qp),
		Duration:       *duration,
	}

	var err error
	if cfg.MsgSize, err = parseSize(*msgSize); err != nil {
		return nil, fmt.Errorf("msg-size: %w", err)
	}
	if cfg.PktSize, err = parseSize(*pktSize); err != nil {
		return nil, fmt.Errorf("pkt-size: %w", err)
	}
	if cfg.RateBps, err = parseRate(*rate); err != nil {
		return nil, fmt.Errorf("rate: %w", err)
	}
	if cfg.USIDBase, err = parseUint16(*usidBase); err != nil {
		return nil, fmt.Errorf("usid-base: %w", err)
	}

	if *dst != "" {
		cfg.Dst, err = netip.ParseAddr(*dst)
		if err != nil {
			return nil, fmt.Errorf("dst: %w", err)
		}
	}
	if *dstMAC != "" {
		cfg.DstMAC, err = net.ParseMAC(*dstMAC)
		if err != nil {
			return nil, fmt.Errorf("dst-mac: %w", err)
		}
	}
	if *peers != "" {
		for _, p := range strings.Split(*peers, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			addr, err := netip.ParseAddr(p)
			if err != nil {
				return nil, fmt.Errorf("peers: %w", err)
			}
			cfg.Peers = append(cfg.Peers, addr)
		}
	}
	if *locator != "" {
		loc, err := netip.ParseAddr(*locator)
		if err != nil {
			return nil, fmt.Errorf("locator: %w", err)
		}
		cfg.Locator = loc
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	switch c.Role {
	case RoleSend, RoleRecv:
	default:
		return fmt.Errorf("role must be send or recv")
	}
	if c.Iface == "" {
		return fmt.Errorf("--iface is required")
	}
	switch c.Proto {
	case ProtoUET, ProtoMRC, ProtoFalcon, ProtoAll:
	default:
		return fmt.Errorf("proto must be uet, mrc, falcon, or all")
	}
	switch c.Encap {
	case EncapUDP6, EncapUDP4, EncapIP6, EncapIP4, EncapAll:
	default:
		return fmt.Errorf("encap must be udp6, udp4, ip6, ip4, or all")
	}
	if c.Role != RoleRecv && (c.Proto == ProtoAll || c.Encap == EncapAll) {
		return fmt.Errorf("all protocols/encapsulations require --role recv")
	}
	if (c.Proto == ProtoMRC || c.Proto == ProtoFalcon) && (c.Encap == EncapIP6 || c.Encap == EncapIP4) {
		return fmt.Errorf("%s requires udp6 or udp4 encapsulation", c.Proto)
	}
	if (c.Proto == ProtoFalcon || c.Proto == ProtoAll) && c.QP > 0xffffff {
		return fmt.Errorf("falcon connection ID (--qp) must fit in 24 bits")
	}
	if (c.Proto == ProtoFalcon || c.Proto == ProtoAll) && (c.FalconCMPort < 1 || c.FalconCMPort > 65535 || c.ConnectTimeout <= 0) {
		return fmt.Errorf("falcon requires a valid --falcon-cm-port and positive --connect-timeout")
	}
	switch c.Pattern {
	case PatternP2P, PatternElephant, PatternMice, PatternOutcast, PatternAllToAll:
	default:
		return fmt.Errorf("invalid pattern")
	}
	switch c.Entropy {
	case EntropyECMP, EntropySRv6:
	default:
		return fmt.Errorf("entropy must be ecmp or srv6")
	}
	if c.Role == RoleSend {
		needsPeers := c.Pattern == PatternOutcast || c.Pattern == PatternAllToAll
		if needsPeers && len(c.Peers) == 0 {
			return fmt.Errorf("--peers required for pattern %s", c.Pattern)
		}
		if !needsPeers && !c.Dst.IsValid() {
			return fmt.Errorf("--dst required for pattern %s", c.Pattern)
		}
	}
	if c.PktSize < 1 || c.PktSize > 9000 {
		return fmt.Errorf("pkt-size out of range")
	}
	if c.MsgSize < c.PktSize {
		return fmt.Errorf("msg-size must be >= pkt-size")
	}
	if c.Window < 1 {
		return fmt.Errorf("window must be >= 1")
	}
	if c.SackEvery < 1 {
		return fmt.Errorf("sack-every must be >= 1")
	}
	if c.Paths < 1 {
		return fmt.Errorf("paths must be >= 1")
	}
	if c.Hops < 1 || c.Hops > 6 {
		return fmt.Errorf("hops must be 1..6")
	}
	if c.Radix < 2 {
		return fmt.Errorf("radix must be >= 2")
	}
	if c.Entropy == EntropySRv6 && !c.Locator.IsValid() {
		return fmt.Errorf("--locator required for srv6 entropy")
	}
	if c.Entropy == EntropySRv6 && !c.Locator.Is6() {
		return fmt.Errorf("locator must be IPv6")
	}
	return nil
}

func (c *Config) IsIPv4() bool {
	return c.Encap == EncapUDP4 || c.Encap == EncapIP4
}

func (c *Config) IsUDP() bool {
	return c.Encap == EncapUDP4 || c.Encap == EncapUDP6
}

func (c *Config) ApplyPatternDefaults() {
	switch c.Pattern {
	case PatternElephant:
		if c.MsgSize < 1024*1024 {
			c.MsgSize = 4 * 1024 * 1024
		}
	case PatternMice:
		c.MsgSize = c.PktSize
	}
}

func parseSize(s string) (int, error) {
	s = strings.TrimSpace(s)
	mult := 1
	upper := strings.ToUpper(s)
	switch {
	case strings.HasSuffix(upper, "KIB"):
		mult = 1024
		s = s[:len(s)-3]
	case strings.HasSuffix(upper, "MIB"):
		mult = 1024 * 1024
		s = s[:len(s)-3]
	case strings.HasSuffix(upper, "KB"):
		mult = 1000
		s = s[:len(s)-2]
	case strings.HasSuffix(upper, "MB"):
		mult = 1000 * 1000
		s = s[:len(s)-2]
	case strings.HasSuffix(upper, "K"):
		mult = 1024
		s = s[:len(s)-1]
	case strings.HasSuffix(upper, "M"):
		mult = 1024 * 1024
		s = s[:len(s)-1]
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	return n * mult, nil
}

func parseRate(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	upper := strings.ToUpper(s)
	var mult uint64 = 1
	switch {
	case strings.HasSuffix(upper, "GBPS"):
		mult = 1_000_000_000
		s = s[:len(s)-4]
	case strings.HasSuffix(upper, "MBPS"):
		mult = 1_000_000
		s = s[:len(s)-4]
	case strings.HasSuffix(upper, "KBPS"):
		mult = 1_000
		s = s[:len(s)-4]
	case strings.HasSuffix(upper, "BPS"):
		s = s[:len(s)-3]
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, err
	}
	return uint64(f * float64(mult)), nil
}

func parseUint16(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, base, 16)
	if err != nil {
		return 0, err
	}
	return uint16(n), nil
}
