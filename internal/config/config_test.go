package config

import (
	"testing"
)

func TestParseMinimalSend(t *testing.T) {
	cfg, err := Parse([]string{
		"--role", "send",
		"--iface", "lo",
		"--dst", "2001:db8::2",
		"--proto", "uet",
		"--encap", "udp6",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Role != RoleSend || cfg.Proto != ProtoUET {
		t.Fatalf("%+v", cfg)
	}
}

func TestMRCRejectsNativeEncap(t *testing.T) {
	_, err := Parse([]string{
		"--role", "recv",
		"--iface", "lo",
		"--proto", "mrc",
		"--encap", "ip6",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseSizesAndRate(t *testing.T) {
	cfg, err := Parse([]string{
		"--role", "recv",
		"--iface", "eth0",
		"--msg-size", "1MiB",
		"--pkt-size", "4KiB",
		"--rate", "100Gbps",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MsgSize != 1024*1024 || cfg.PktSize != 4096 {
		t.Fatalf("sizes %d %d", cfg.MsgSize, cfg.PktSize)
	}
	if cfg.RateBps != 100_000_000_000 {
		t.Fatalf("rate %d", cfg.RateBps)
	}
}

func TestOutcastRequiresPeers(t *testing.T) {
	_, err := Parse([]string{
		"--role", "send",
		"--iface", "lo",
		"--pattern", "outcast",
		"--dst", "2001:db8::1",
	})
	if err == nil {
		t.Fatal("expected peers required")
	}
}
