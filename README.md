# Super Intelligence Traffic Generator (SITG)

SITG is a Linux traffic generator for **Ultra Ethernet Transport (UET)**, **Multipath Reliable Connection (MRC)**, and **OCP Falcon** flows. It injects live frames with `AF_PACKET`, runs a simplified reliable window between a send and recv process, and can optionally source-route packets with **SRv6 uSID** destinations.

Headers are a recognizable subset of UET, MRC, and Falcon for lab and fabric testing—not a full specification implementation.

## Requirements

- Linux
- Go 1.26+ (see `go.mod`)
- `CAP_NET_RAW` (or root) to open raw sockets
- An IPv4 or IPv6 address on `--iface` matching the chosen encapsulation
- The kernel routing table must provide a route on `--iface`; SITG resolves the next-hop MAC automatically with ARP/NDP.

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
  --dst 2001:db8::2 \
  --qp 1 --rate 10Gbps --duration 10s
```

Match `--proto`, `--encap`, `--qp`, and (for native UET) `--ip-proto` on both sides,
or run a receiver with `--proto all` to accept all supported wire formats.

## Receive all protocols and variants

```bash
sudo ./sitg --role recv --iface eth0 --proto all --duration 0s --qp 1
```

One receiver accepts UET, MRC, and Falcon simultaneously, using every supported
IPv4/IPv6 encapsulation: UDP for all three protocols and native IP for UET.
Plain and SRv6-encapsulated traffic are both detected automatically, regardless
of `--entropy`. Only address families available on the interface are enabled.
Native UET uses the configured `--ip-proto` (default `253`).

`--proto all` implies `--encap all` unless an explicit encapsulation is provided.
Use `--proto all --encap udp6` to restrict the wire format, or
`--proto uet --encap all` to receive all UET variants. Senders select one concrete
protocol and encapsulation. `--duration 0s` keeps the receiver running until SIGINT.

`--qp` still selects the UET/MRC QP and Falcon CM service. Reliability state is
separate for each protocol, encapsulation, peer, local IP, QP and plain/SRv6
variant; Falcon connections retain their negotiated CIDs and sequence windows.
ACKs use the incoming protocol and encapsulation and return directly to the inner
source IP. Progress and final statistics aggregate all accepted traffic.

Falcon setup listens on the selected interface's IPv4 and IPv6 addresses at
`--falcon-cm-port`, where UDP encapsulations are enabled. The receiver supports
up to 4096 UET/MRC flows and 1024 active Falcon connections per run; new flows
beyond those limits are rejected or ignored. UET/MRC flow state remains until exit.

## CLI reference

| Flag | Default | Description |
|------|---------|-------------|
| `--role` | `send` | `send` or `recv` |
| `--iface` | *(required)* | Network interface for AF_PACKET |
| `--proto` | `uet` | `uet`, `mrc`, `falcon`, or `all` (receiver only) |
| `--encap` | `udp6` | Encapsulation; `all` for receivers (implicit with `--proto all`) |
| `--ip-proto` | `253` | IPv4 protocol / IPv6 next-header for native UET |
| `--dst` | | Destination IP (sender; required for most patterns) |
| `--dst-mac` | *(automatic)* | Optional next-hop MAC override; otherwise use kernel routing and ARP/NDP |
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
| `--qp` | `1` | Queue pair / PDC identifier; Falcon CM service and first local receive CID |
| `--falcon-cm-port` | `4795` | TCP port for SITG Falcon connection setup |
| `--connect-timeout` | `5s` | Falcon setup and final window-drain timeout |

### Encapsulation (`--encap`)

| Value | Protocol | Wire shape |
|-------|----------|------------|
| `udp6` | UET, MRC, or Falcon | IPv6 + UDP (UET port **4793**, MRC port **4791**) |
| `udp4` | UET, MRC, or Falcon | IPv4 + UDP |
| `ip6` | UET only | Native IPv6 + 4-byte entropy header |
| `ip4` | UET only | Native IPv4 + 4-byte entropy header (DF set) |

UET over UDP uses UDP source port as entropy and sets the UDP checksum to `0`. Native UET places a 4-byte entropy header after the IP header; configure the IP protocol with `--ip-proto` (default `253` until IANA assigns one).

MRC and Falcon require `udp6` or `udp4`.

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
  --dst 2001:db8::10 \
  --pattern p2p --msg-size 1MiB --pkt-size 4096 --rate 100Gbps --duration 30s --qp 1
```

### MRC over RoCEv2-style UDP

```bash
sudo ./sitg --role recv --iface eth0 --proto mrc --encap udp6 --qp 7 --duration 60s

sudo ./sitg --role send --iface eth0 --proto mrc --encap udp6 \
  --dst 2001:db8::20 \
  --pattern elephant --rate 200Gbps --window 512 --rto 2ms --qp 7 --duration 60s
```

### OCP Falcon lab traffic

```bash
sudo ./sitg --role recv --iface eth0 --proto falcon --encap udp6 --qp 7 --duration 60s
sudo ./sitg --role send --iface eth0 --proto falcon --encap udp6 \
  --dst 2001:db8::20 --qp 7 --duration 30s
```

Falcon uses the v1.1 Push Data base header and request length, and BACK/EACK
acknowledgements from the [OCP Falcon specification](https://github.com/opencomputeproject/OCP-NET-Falcon).
SITG carries these headers directly over cleartext UDP port **4794**, a local lab
convention, not an assigned Falcon port or the specification's PSP/ESP envelope.
Both peers must use SITG's lab framing; this does not interoperate with secured
Falcon NICs. IPv4, IPv6, ECMP and SRv6 use the same options as MRC.

Falcon connections are established automatically before traffic starts. SITG's
versioned TCP control plane (`sitg-falcon-cm/1`) listens on `--falcon-cm-port`
(default **4795**) at the interface's selected IP address (both address families with `--encap all`). This is a SITG control
protocol, not a standardized Falcon setup packet. With SRv6, control traffic uses
ordinary IP routing to the inner peer address; data retains SRv6 encapsulation.

Use matching `--qp` values to select the receiver's CM service. Each endpoint
allocates its own 24-bit receive CID, starting at `--qp` and increasing for each
connection. Data carries the receiver's CID; acknowledgements carry the sender's
CID. The IDs are logged at setup and need not be equal. Multiple senders and
fan-out peers have independent sequence windows and acknowledgement state.
CIDs are not reused during a process lifetime; drain old traffic before restarting
a receiver with the same CID range.

Setup negotiates encapsulation, maximum packet payload, and an in-flight window
bounded by both endpoints and SITG's 64-packet selective-ACK implementation.
PSN and receive-window bases initialize to zero per connection. Mismatched
services/encapsulations are rejected. Data from unknown CIDs or other source IPs
is ignored, and no data is sent until all peer setups complete. `--duration` starts
after sender setup; the receiver's duration includes its listening time.
`--connect-timeout` bounds each peer's setup and the sender's final window drain.
The TCP connection stays open during the run; closing it tears down the connection
state. A sender exits with an error if a peer disconnects during transfer.

Message ID maps to the request sequence number. The payload is opaque lab data;
RDMA ULP headers, message offsets, PSP/ESP, pull transactions, NACK/resync and
congestion control are not implemented. Falcon has no RTX flag, so retransmissions
retain the original PSN and do not increment RTX-flagged stats. EACK translates
the selective window into Falcon's base-relative 128-bit data ACK/Rx bitmaps;
request-window and congestion metadata remain zero.

### Native UET (no UDP)

```bash
sudo ./sitg --role recv --iface eth0 --proto uet --encap ip6 --ip-proto 253 --qp 1 --duration 30s

sudo ./sitg --role send --iface eth0 --proto uet --encap ip6 --ip-proto 253 \
  --dst 2001:db8::30 \
  --rate 40Gbps --duration 30s --qp 1
```

### SRv6 uSID packet spray

```bash
sudo ./sitg --role recv --iface eth0 --proto uet --encap udp6 \
  --entropy srv6 --locator fc00:: --paths 128 --hops 3 --radix 32 --qp 1 --duration 60s

sudo ./sitg --role send --iface eth0 --proto uet --encap udp6 \
  --dst 2001:db8::40 \
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
  --dst 2001:db8::1 --qp 1 --rate 25Gbps --duration 120s
```

### Outcast / all-to-all from one sender

```bash
sudo ./sitg --role send --iface eth0 --proto uet --encap udp6 \
  --pattern outcast \
  --peers 2001:db8::2,2001:db8::3,2001:db8::4 \
  \
  --rate 50Gbps --duration 30s --qp 1
```

Run a matching `--role recv` on each peer (same `--qp`, or distinct QPs per peer if isolating sessions). Each peer uses its own route and next-hop neighbor on `--iface`; no MAC arguments or prepopulated neighbor entries are required.

### Mice vs elephant mix

```bash
# Short messages
sudo ./sitg --role send --iface eth0 --proto uet --encap udp6 \
  --dst 2001:db8::2 --pattern mice --rate 5Gbps --qp 1 --duration 30s

# Bulk transfers
sudo ./sitg --role send --iface eth0 --proto uet --encap udp6 \
  --dst 2001:db8::2 --pattern elephant --msg-size 16MiB --rate 50Gbps --qp 2 --duration 30s
```

Use different `--qp` values so sessions stay independent on a shared receiver (receivers currently filter on one `--qp` per process—start one recv per QP if needed).

### Loopback smoke test

```bash
sudo ./sitg --role recv --iface lo --proto uet --encap udp6 --qp 1 --duration 5s

sudo ./sitg --role send --iface lo --proto uet --encap udp6 \
  --dst ::1 --qp 1 --rate 50Mbps --duration 2s
```

Loopback often shows duplicate receives (TX and RX copies); unique byte counts and SACKs are still meaningful.

MAC discovery runs before the sender traffic clock starts and is bounded by
`--connect-timeout`. For routed traffic, SITG resolves the gateway rather than the
remote host. For SRv6, it looks up each outer uSID destination. Neighbor lookups
are scoped to `--iface`; a cold cache triggers a small UDP discard-port probe
to let the kernel perform ARP/NDP. Loopback uses a zero MAC automatically.
`--dst-mac` remains available to override discovery for special lab setups.

## Statistics

Both roles print a one-line progress update about once per second, then a final report on SIGINT, duration end, or (sender) window drain.

**Sender:** packets sent, retransmissions, SACKs received, bytes sent / acknowledged, inferred loss, goodput, SACK RTT (min/mean/max), total time.

**Receiver:** packets received, duplicates, RTX-flagged retransmissions, SACKs sent, unique bytes, gaps open, goodput, total time.

## Notes

- IP fragmentation is not used; keep `--pkt-size` within the path MTU after headers (and SRv6 outer header when enabled).
- Reliability is a simplified window + SACK + RTO model for traffic generation, not full UET CMS/PDS or MRC congestion control.
- Non-Linux builds compile stub link code but cannot inject packets.
