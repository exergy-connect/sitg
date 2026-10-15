# Super Intelligence Traffic Generator (SITG)

SITG is a Linux traffic generator for **Ultra Ethernet Transport (UET)**, **Multipath Reliable Connection (MRC)**, and **OCP Falcon** flows. It injects live frames with `AF_PACKET`, runs a simplified reliable window between a send and recv process, and can optionally source-route packets with **SRv6 uSID** destinations.

UET traffic uses UET 1.0.1 RUD Request headers, Standard SES Write requests, ACK_CC selective acknowledgments, and a CRC32C trailer covering the inner IP addresses through the transport payload. MRC traffic uses OCP MRC 1.0 Write and Reliability SACK wire formats; Falcon support remains a subset for lab and fabric testing.

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
`--proto uet --encap all` to receive all UET variants. Senders select one concrete encapsulation and either a single protocol or
`mixed` (UDP only). `--duration 0s` keeps the receiver running until SIGINT.

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
| `--proto` | `uet` | `uet`, `mrc`, `falcon`, `mixed` (sender), or `all` (receiver) |
| `--switch-every` | `1s` | Mixed sender switches after this duration, packet count, or payload size |
| `--encap` | `udp6` | Encapsulation; `all` for receivers (implicit with `--proto all`) |
| `--ip-proto` | `253` | IPv4 protocol / IPv6 next-header for native UET |
| `--dst` | | Destination IP (sender; required for most patterns) |
| `--dst-mac` | *(automatic)* | Optional next-hop MAC override; otherwise use kernel routing and ARP/NDP |
| `--pattern` | `p2p` | Traffic pattern (see below) |
| `--peers` | | Comma-separated peer IPs for `outcast` / `alltoall` |
| `--msg-size` | `32KiB` | Message size (`KiB`/`MiB`/`KB`/`MB`/`K`/`M` suffixes) |
| `--pkt-size` | `4096` | Payload bytes per packet |
| `--rate` | `10Gbps` | Send rate (`Gbps`/`Mbps`/`Kbps`/`bps` or `Gpps`/`Mpps`/`Kpps`/`pps`) |
| `--duration` | `10s` | Nonnegative integer seconds (`10` or `10s`); sender then drains the window; receiver exits when set |
| `--window` | `256` | In-flight packet window |
| `--sack-every` | `16` | Receiver emits a SACK every N data packets |
| `--rto` | `10ms` | Retransmission timeout (oldest hole; linear then exponential backoff) |
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

UET uses preconfigured symmetric 16-bit PDC IDs (`--qp`, at most 65535), rather than negotiating PDC establishment. SES message IDs wrap at 16 bits. Requests carry message boundaries, offsets, lengths, and the retransmission flag. ACK_CC translates the internal next-expected counter to UET's inclusive CACK and uses an aligned 64-bit SACK window; higher selective bits wait for a later ACK. The congestion state is idle NSCC; this is not a full UET congestion-control implementation. Both endpoints must use the updated wire format; older SITG private UET packets are incompatible.

SITG binds the selected protocol UDP ports on its local interface addresses on both senders and receivers, attaching a drop-all UDP socket filter while AF_PACKET processes the frames. The filter discards kernel copies before queueing, so no drain goroutines or userspace receive buffers are needed. This prevents kernel-generated ICMP port-unreachable replies. Port conflicts fail at startup, and the bindings are released on exit.

Native UET also registers filtered raw-IP sockets for the configured `--ip-proto` on both endpoints (including the All protocols receiver). This prevents IPv4 protocol-unreachable and IPv6 unrecognized-next-header ICMP errors without receive queues or drain loops.

UET over UDP uses UDP source port as entropy and sets the UDP checksum to `0`. Native UET places a 4-byte entropy header after the IP header; configure the IP protocol with `--ip-proto` (default `253` until IANA assigns one).

MRC and Falcon require `udp6` or `udp4`.

MRC emits standard Write First/Middle/Last/Only opcodes (`0xc6`, `0xc7`, `0xc8`, `0xca`), METH and per-packet RETH, BTH ACK/retransmission flags, four-byte alignment padding, and a RoCE invariant CRC trailer. Reliability SACK (`0xdc`) carries SETH and idle NSCC state, an inclusive 24-bit CACK, a signed SACK base offset, the selective bitmap, and reflected request entropy. UDP checksums include the final trailer. CRC validation is not performed.

The lab profile uses preconfigured symmetric 24-bit QPs, a synthetic memory region (key 1, virtual address equal to the message byte offset), and 16-bit wrapping message IDs. It does not negotiate real RDMA resources or implement full congestion control. Runs must end before the 24-bit packet sequence space wraps. Both endpoints need the updated binary.


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
  --pattern elephant --rate 200Gbps --window 512 --qp 7 --duration 60s
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

### Alternating UET, Falcon, and MRC

Use `--proto mixed` to cycle **UET → Falcon → MRC → UET** over UDP4 or
UDP6. Start a receiver with `--proto all` and the same `--qp` first.

```bash
sudo ./sitg --role recv --iface eth0 --proto all --qp 1 --duration 0s
sudo ./sitg --role send --iface eth0 --proto mixed --encap udp4 \
  --dst 192.0.2.2 --qp 1 --pkt-size 1200 --rate 100Mbps \
  --duration 30s --switch-every 100packets
```

`--switch-every` applies to each protocol phase:

| Value | Switch after |
|-------|--------------|
| `1s`, `250ms` | Elapsed time since the phase started |
| `100packets` (or `100pkts`) | 100 new data packets |
| `1Mb` | 1,000,000 payload bits (125,000 bytes) |
| `1MB` | 1,000,000 payload bytes |
| `1MiB` | 1,048,576 payload bytes |

Bit/byte suffixes are case-sensitive. Bit thresholds round up to whole bytes;
the last packet is shortened to meet a size threshold exactly. Packet and size
counts aggregate across peers and exclude headers, ACKs, and retries. Time
switches occur when the sender loop next runs, so scheduling can delay them.

Each protocol and peer retains independent sequence windows and message offsets
across switches. Falcon setup completes for every peer before the traffic clock
starts, and negotiated payload/window limits apply. Only new traffic switches:
outstanding packets from earlier phases can still be retried and acknowledged.
`--rate` is shared across protocols and retries. `--duration` ends new traffic,
then all windows drain with `--connect-timeout` as the deadline. The final report
includes original packet counts, payload bytes, and retries for each protocol.

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

**Sender:** packets sent, retransmissions, SACKs received, bytes sent / acknowledged, retransmission ratio, goodput, SACK RTT (min/mean/max), total time.

**Receiver:** packets received, duplicates, RTX-flagged retransmissions, SACKs sent, unique bytes, gaps open, goodput, total time.

The retransmission ratio is retries divided by all transmitted packets. It is
not a measurement of network packet loss: delayed ACKs or process scheduling
can cause retries even when every original packet arrives. The default 10 ms
RTO allows for ACK batching and userspace scheduling; tune `--rto` to your lab.

## Notes

- IP fragmentation is not used; keep `--pkt-size` within the path MTU after headers (and SRv6 outer header when enabled).
- Reliability is a simplified window + SACK + RTO model for traffic generation, not full UET CMS/PDS or MRC congestion control.
- Non-Linux builds compile stub link code but cannot inject packets.

Packet rates such as `--rate 1000pps` count each transmitted data packet once, regardless of packet size. Falcon and mixed mode also count retransmissions against the rate.

## Traffic scenarios

Run a sequence of traffic steps from a text file:

```sh
sitg --scenario traffic.txt --iface eth1 --encap udp4 --dst 192.0.2.2
```

Each nonempty line contains CLI parameters for one session. Blank lines and
`#` comment lines are skipped; inline comments at word boundaries are also
supported. A line may optionally begin with `sitg`. Single and double quotes
and backslash escapes are supported; shell substitutions are not expanded.

Example `traffic.txt`:

```text
# Start slowly, then increase load
--proto uet --rate 100pps --duration 5s
--proto falcon --rate "10Mbps" --duration 10s # Falcon phase
--proto mixed --rate 1Kpps --duration 15s --switch-every 100packets
```

Flags supplied alongside `--scenario` initialize the parameters. Each line
changes only the flags it specifies; all other parameters carry forward from
the CLI and previous lines. For example, after `--rate 2pps --duration 8s`, a
line containing only `--proto falcon` keeps that rate and duration.
All steps are validated before traffic starts. Steps run in file order, each
finishing its session and closing its socket before the next starts. Errors
stop playback and identify the file and line. Ctrl-C stops playback. An unlimited
receiver (`--duration 0s`) stays on that step until interrupted.
Use `--scenario -` to read from standard input.

The Artificial Tango choreography is built into the binary; no scenario file
is needed:

```sh
sitg --scenario artificial-tango --iface eth1 --encap udp4 --dst 192.0.2.2
```

See [the scenario notes](scenarios/README.md) for receiver setup and approximate
song timing. A custom file can still be passed to `--scenario`.
