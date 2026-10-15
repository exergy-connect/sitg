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

func TestFalconConfig(t *testing.T) {
	for _, encap := range []string{"udp4", "udp6", "ip4", "ip6"} {
		for _, qp := range []string{"1", "16777215", "16777216"} {
			_, err := Parse([]string{"--role", "recv", "--iface", "lo", "--proto", "falcon", "--encap", encap, "--qp", qp})
			valid := (encap == "udp4" || encap == "udp6") && qp != "16777216"
			if (err == nil) != valid {
				t.Fatalf("encap=%s qp=%s err=%v", encap, qp, err)
			}
		}
	}
}

func TestFalconCMOptions(t *testing.T) {
	for _, args := range [][]string{{"--falcon-cm-port", "0"}, {"--falcon-cm-port", "65536"}, {"--connect-timeout", "0s"}, {"--connect-timeout", "-1s"}} {
		_, err := Parse(append([]string{"--role", "recv", "--iface", "lo", "--proto", "falcon"}, args...))
		if err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	c, err := Parse([]string{"--role", "recv", "--iface", "lo", "--proto", "falcon", "--falcon-cm-port", "12345", "--connect-timeout", "2s"})
	if err != nil {
		t.Fatal(err)
	}
	if c.FalconCMPort != 12345 || c.ConnectTimeout.String() != "2s" {
		t.Fatalf("%+v", c)
	}
}

func TestReceiveAll(t *testing.T) {
	for _, proto := range []string{"all", "uet", "mrc", "falcon"} {
		c, err := Parse([]string{"--role", "recv", "--iface", "lo", "--proto", proto, "--encap", "all"})
		if err != nil || c.Encap != EncapAll {
			t.Fatalf("%s: %+v %v", proto, c, err)
		}
	}
	c, err := Parse([]string{"--role", "recv", "--iface", "lo", "--proto", "all"})
	if err != nil || c.Encap != EncapAll {
		t.Fatalf("all must imply all encapsulations: %+v %v", c, err)
	}
	c, err = Parse([]string{"--role", "recv", "--iface", "lo", "--proto", "all", "--encap", "udp6"})
	if err != nil || c.Encap != EncapUDP6 {
		t.Fatalf("explicit filter lost: %+v %v", c, err)
	}
	for _, args := range [][]string{{"--proto", "all"}, {"--encap", "all"}} {
		if _, err := Parse(append([]string{"--iface", "lo", "--dst", "::1"}, args...)); err == nil {
			t.Fatalf("sender accepted %v", args)
		}
	}
	for _, args := range [][]string{{"--qp", "16777216"}, {"--falcon-cm-port", "0"}, {"--connect-timeout", "0s"}} {
		if _, err := Parse(append([]string{"--role", "recv", "--iface", "lo", "--proto", "all"}, args...)); err == nil {
			t.Fatalf("all bypassed Falcon validation: %v", args)
		}
	}
}
