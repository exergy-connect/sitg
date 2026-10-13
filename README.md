# Super Intelligence Traffic Generator (SITG)

SITG is a Linux traffic generator for **Ultra Ethernet Transport (UET)** and **Multipath Reliable Connection (MRC)** flows. It injects live frames with `AF_PACKET`, runs a simplified reliable window between a send and recv process, and can optionally source-route packets with **SRv6 uSID** destinations.

Headers are a recognizable subset of UET and MRC for lab and fabric testing—not a full specification implementation.

## Requirements

- Linux
- Go 1.26+ (see `go.mod`)
- `CAP_NET_RAW` (or root) to open raw sockets
- An IPv4 or IPv6 address on `--iface` matching the chosen encapsulation
- Destination MAC via `--dst-mac`, or a resolved neighbor entry

## Build

```bash
go build -o sitg ./cmd/sitg
go test ./...
```

CI builds the Linux amd64 binary on push and pull request (see [`.github/workflows/build.yml`](.github/workflows/build.yml)).

## Quick start

Run a receiver, then a sender on the same QP. Both print progress about once per second and a final stats report on exit.

```bash
# Receiver
sudo ./sitg --role recv --iface eth0 --proto uet --encap udp6 --qp 1 --duration 60s

# Sender
sudo ./sitg --role send --iface eth0 --proto uet --encap udp6 \
  --dst 2001:db8::2 --dst-mac aa:bb:cc:dd:ee:ff \
  --qp 1 --rate 10Gbps --duration 10s
```

Match `--proto`, `--encap`, `--qp`, and (for native UET) `--ip-proto` on both sides.

## CLI reference

| Flag | Default | Description |
|------|---------|-------------|
| `--role` | `send` | `send` or `recv` |
| `--iface` | *(required)* | Network interface for AF_PACKET |
| `--proto` | `uet` | `uet` or `mrc` |
| `--encap` | `udp6` | Encapsulation (see below) |
| `--ip-proto` | `253` | IPv4 protocol / IPv6 next-header for native UET |
| `--dst` | | Destination IP (sender; required for most patterns) |
| `--dst-mac` | | Destination MAC (optional if neighbor is known) |
| `--pattern` | `p2p` | Traffic pattern (see below) |
| `--peers` | | Comma-separated peer IPs for `outcast` / `alltoall` |
| `--msg-size` | `32KiB` | Message size (`KiB`/`MiB`/`KB`/`MB`/`K`/`M` suffixes) |
| `--pkt-size` | `4096` | Payload bytes per packet |
| `--rate` | `10Gbps` | Send rate (`Gbps`/`Mbps`/`Kbps`/`bps`) |
| `--duration` | `10s` | Run length; sender then drains the window; receiver exits when set |
| `--window` | `256` | In-flight packet window |
| `--sack-every` | `16` | Receiver emits a SACK every N data packets |
| `--rto` | `1ms` | Retransmission timeout (oldest hole; linear then exponential backoff) |
| `--entropy` | `ecmp` | `ecmp` or `srv6` |
| `--locator` | `fc00::` | 32-bit SRv6 locator prefix |
| `--paths` | `64` | Number of entropy values / SRv6 paths |
| `--hops` | `3` | uSID hops per path (1–6) |
| `--radix` | `32` | Fabric radix for path encoding |
| `--usid-base` | `0x0100` | Base 16-bit uSID value |
| `--qp` | `1` | Queue pair / PDC identifier |

### Encapsulation (`--encap`)

| Value | Protocol | Wire shape |
|-------|----------|------------|
| `udp6` | UET or MRC | IPv6 + UDP (UET port **4793**, MRC port **4791**) |
| `udp4` | UET or MRC | IPv4 + UDP |
| `ip6` | UET only | Native IPv6 + 4-byte entropy header |
| `ip4` | UET only | Native IPv4 + 4-byte entropy header (DF set) |

UET over UDP uses UDP source port as entropy and sets the UDP checksum to `0`. Native UET places a 4-byte entropy header after the IP header; configure the IP protocol with `--ip-proto` (default `253` until IANA assigns one).

MRC requires `udp6` or `udp4`.

### Entropy and SRv6 (`--entropy`)

- **`ecmp`** — Path entropy in the encapsulation field (UDP source port, or native entropy header). Also set as the IPv6 flow label when applicable.
- **`srv6`** — Outer IPv6 header whose destination is a uN-style uSID address: 32-bit locator + up to six 16-bit uSIDs. The inner packet keeps `--encap`. Path `i` uses `hop_k = usid-base + (i / radix^k) % radix`. Outer next-header is `41` (IPv6) or `4` (IPv4). Requires an IPv6 address on the interface for the outer source.

### Traffic patterns (`--pattern`)

| Pattern | Behavior |
|---------|----------|
| `p2p` | Single destination (`--dst`) |
| `elephant` | Large messages (defaults toward multi‑MiB if `--msg-size` is small) |
| `mice` | One packet per message (`msg-size = pkt-size`) |
| `outcast` | Round-robin across `--peers` |
| `alltoall` | Fan-out across `--peers` (same peer rotation for a single sender) |

**Incast:** start multiple senders aimed at one receiver (same `--qp` on the receiver, or separate QPs if you want isolated sessions).

## Common use cases

### Point-to-point UET over UDP/IPv6

```bash
sudo ./sitg --role recv --iface eth0 --proto uet --encap udp6 --qp 1 --duration 30s

sudo ./sitg --role send --iface eth0 --proto uet --encap udp6 \
  --dst 2001:db8::10 --dst-mac 02:00:00:00:00:10 \
  --pattern p2p --msg-size 1MiB --pkt-size 4096 --rate 100Gbps --duration 30s --qp 1
```

### MRC over RoCEv2-style UDP

```bash
sudo ./sitg --role recv --iface eth0 --proto mrc --encap udp6 --qp 7 --duration 60s

sudo ./sitg --role send --iface eth0 --proto mrc --encap udp6 \
  --dst 2001:db8::20 --dst-mac 02:00:00:00:00:20 \
  --pattern elephant --rate 200Gbps --window 512 --rto 2ms --qp 7 --duration 60s
```

### Native UET (no UDP)

```bash
sudo ./sitg --role recv --iface eth0 --proto uet --encap ip6 --ip-proto 253 --qp 1 --duration 30s

sudo ./sitg --role send --iface eth0 --proto uet --encap ip6 --ip-proto 253 \
  --dst 2001:db8::30 --dst-mac 02:00:00:00:00:30 \
  --rate 40Gbps --duration 30s --qp 1
```

### SRv6 uSID packet spray

```bash
sudo ./sitg --role recv --iface eth0 --proto uet --encap udp6 \
  --entropy srv6 --locator fc00:: --paths 128 --hops 3 --radix 32 --qp 1 --duration 60s

sudo ./sitg --role send --iface eth0 --proto uet --encap udp6 \
  --dst 2001:db8::40 --dst-mac 02:00:00:00:00:40 \
  --entropy srv6 --locator fc00:: --paths 128 --hops 3 --radix 32 --usid-base 0x0100 \
  --rate 100Gbps --duration 60s --qp 1
```

The fabric must forward the outer uSID destinations (static shift-and-forward). The inner destination remains `--dst`.

### Many-to-one incast

```bash
# One receiver
sudo ./sitg --role recv --iface eth0 --proto uet --encap udp6 --qp 1 --window 1024 --duration 120s

# Several senders (same dst, same qp)
sudo ./sitg --role send --iface eth0 --proto uet --encap udp6 \
  --dst 2001:db8::1 --dst-mac ... --qp 1 --rate 25Gbps --duration 120s
```

### Outcast / all-to-all from one sender

```bash
sudo ./sitg --role send --iface eth0 --proto uet --encap udp6 \
  --pattern outcast \
  --peers 2001:db8::2,2001:db8::3,2001:db8::4 \
  --dst-mac 02:00:00:00:00:02 \
  --rate 50Gbps --duration 30s --qp 1
```

Run a matching `--role recv` on each peer (same `--qp`, or distinct QPs per peer if isolating sessions). When peers do not share one L2 adjacency, set neighbor entries or run separate senders with per-destination `--dst-mac`.

### Mice vs elephant mix

```bash
# Short messages
sudo ./sitg --role send --iface eth0 --proto uet --encap udp6 \
  --dst 2001:db8::2 --dst-mac ... --pattern mice --rate 5Gbps --qp 1 --duration 30s

# Bulk transfers
sudo ./sitg --role send --iface eth0 --proto uet --encap udp6 \
  --dst 2001:db8::2 --dst-mac ... --pattern elephant --msg-size 16MiB --rate 50Gbps --qp 2 --duration 30s
```

Use different `--qp` values so sessions stay independent on a shared receiver (receivers currently filter on one `--qp` per process—start one recv per QP if needed).

### Loopback smoke test

```bash
sudo ./sitg --role recv --iface lo --proto uet --encap udp6 --qp 1 --duration 5s

sudo ./sitg --role send --iface lo --proto uet --encap udp6 \
  --dst ::1 --dst-mac 00:00:00:00:00:00 --qp 1 --rate 50Mbps --duration 2s
```

Loopback often shows duplicate receives (TX and RX copies); unique byte counts and SACKs are still meaningful.

## Statistics

Both roles print a one-line progress update about once per second, then a final report on SIGINT, duration end, or (sender) window drain.

**Sender:** packets sent, retransmissions, SACKs received, bytes sent / acknowledged, inferred loss, goodput, SACK RTT (min/mean/max), total time.

**Receiver:** packets received, duplicates, RTX-flagged retransmissions, SACKs sent, unique bytes, gaps open, goodput, total time.

## Notes

- IP fragmentation is not used; keep `--pkt-size` within the path MTU after headers (and SRv6 outer header when enabled).
- Reliability is a simplified window + SACK + RTO model for traffic generation, not full UET CMS/PDS or MRC congestion control.
- Non-Linux builds compile stub link code but cannot inject packets.
