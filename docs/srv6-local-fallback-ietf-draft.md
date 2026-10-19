---
title: "Encapsulated SRv6 Path Steering with Local Decapsulation Fallback"
abbrev: SRv6 Local Fallback
docname: draft-vanbemmel-srv6-local-decapsulation-fallback-00
category: info
ipr: trust200902
submissiontype: IETF
stand_alone: true
pi:
  toc: 'yes'
  sortrefs: 'yes'
  symrefs: 'yes'
author:
  - name: Jeroen van Bemmel
    ins: J. van Bemmel
    email: jvb127@gmail.com
normative:
  RFC8200:
  RFC8986:
  RFC9800:
informative:
  I-D.filsfils-srv6ops-srv6-ai-backend: I-D.filsfils-srv6ops-srv6-ai-backend-05

--- abstract

This document describes a forwarding design that combines sender-selected SRv6 paths with network-provided delivery recovery. An outer IPv6 header carries the preferred path, while the inner IPv6 destination independently identifies the receiving endpoint. More-specific forwarding entries implement path steering. A covering route invokes End.DT6 when the applicable more-specific route is withdrawn, allowing a fabric node to decapsulate locally and route the inner packet toward its destination. Recovery depends on failure detection, forwarding-state updates, and ordinary IPv6 reachability. An FRR/Linux fabric illustrates the design.

--- middle

# Introduction

AI backend fabrics and other multipath networks allow a sending endpoint to choose paths to distribute load or avoid congestion. A link or node failure can make a selected path unusable before the sender learns of the failure or chooses a replacement.

The design in this document preserves the sender's preferred path while the corresponding forwarding state exists. Each participating fabric node also has a less-specific route that provides local decapsulation fallback. Once failure handling removes the applicable path route from forwarding, the covering route can take over and ordinary IPv6 routing can attempt delivery using the inner destination.

The outer path and inner destination have separate responsibilities: the sender controls preferred traffic placement, and the network provides delivery recovery. After fallback, the packet no longer carries the discarded path instructions. The network does not need to construct a replacement SRv6 program or wait for the sender to react.

The design combines existing SRv6 endpoint behaviors with longest-prefix route selection. Recovery time depends on failure detection and routing convergence.

The Internet-Draft *SRv6 for Deterministic Path Placement in AI Backends* {{I-D.filsfils-srv6ops-srv6-ai-backend}} describes NIC-selected SRv6 paths for Multipath Reliable Connection (MRC) traffic. This document adds a complementary network recovery design: a covering decapsulation route allows ordinary destination routing to take over when a programmed-path route becomes unavailable. Sender path selection and transport recovery can continue to operate alongside this network fallback.

# Scope and Terminology

A *programmed-path route* is a forwarding entry directing the outer packet toward the next instruction selected by the sender. A *fallback route* is a covering prefix associated with local End.DT6 processing and a chosen IPv6 lookup table. *Ordinary destination routing* provides reachability to the inner IPv6 destination in that table.

The design applies within an administratively controlled SRv6 domain where local decapsulation and subsequent destination routing are authorized at every participating node. The sender may be a host, NIC, or ingress encapsulator. The forwarding mechanism is independent of the transport, its path-selection algorithm, and the provisioning protocol.

The concrete packet model illustrated here carries an IPv6 packet inside an outer IPv6 header, with the complete compressed path in the outer Destination Address and no Segment Routing Header (SRH). Longer programs requiring an SRH are outside the example's scope. End.DT6 rejects an SRH with nonzero Segments Left.

# Forwarding Model

## Packet Construction and Preferred Forwarding

The sender retains the receiving endpoint's address as the inner IPv6 destination {{RFC8200}}. It constructs an outer IPv6 header whose Destination Address encodes the selected path. The example uses a 32-bit common block and 16-bit compressed instructions; NEXT-CSID processing follows {{RFC9800}}. The outer header identifies IPv6 as its encapsulated payload.

Participating nodes install the local instructions and onward routes needed by the supported programs. A local instruction advances the program, and the resulting outer destination undergoes another forwarding lookup. Remote programmed-path routes direct the packet toward the selected next node. A normal terminal decapsulation entry delivers the inner packet when the program completes.

The sender and the provisioned forwarding state must agree on the encoding, instruction widths, terminal behavior, and permitted next hops. An encoded node sequence constrains physical forwarding only to the extent that the installed routes constrain those next hops.

## Covering Decapsulation Route

Each participating node installs a fallback prefix covering the outer destinations for which it accepts fallback. The selected route invokes End.DT6 with a designated IPv6 table. For an eligible encapsulated IPv6 packet, this removes the outer encapsulation and submits the exposed packet to a lookup in that table, as specified in Section 4.6 of {{RFC8986}}.

The proposal binds this behavior to a covering prefix so that the absence of a more-specific programmed-path route exposes the decapsulation action. Implementations must support the prefix-based local behavior and packet form used by the deployment.

The lookup table may be the ordinary destination table or an appropriately isolated tenant table. Every node that can perform fallback needs usable destination routes in the selected table.

## Route Selection and Withdrawal

A node may have a local `/48` NEXT-CSID entry, remote `/48` programmed-path routes, and a covering `/32` End.DT6 entry. Longest-prefix matching selects the applicable `/48` while it remains installed. Following local program advancement, the same ordering applies to the new outer destination.

When the applicable remote `/48` is withdrawn from forwarding, the `/32` can become the selected entry. This assumes that no other matching, more-specific route remains. Route preference between routes of the same length does not replace the required prefix relationship.

A failed forwarding attempt does not itself cause a second lookup using the less-specific route. An installed route pointing at an unusable adjacency can continue to blackhole packets. Failure detection and route management must remove or invalidate that route in a way that actually exposes the covering entry. Recursive resolution, alternate routes, and discard entries must be considered when checking this property.

Once decapsulated, the inner packet follows ordinary routing without the original program. Subsequent packets from the sender can still use the same outer program and independently encounter fallback until path state is restored or the sender chooses another program.

# Failure Handling

## Detection and Convergence

A physical link-down event can cause withdrawal of an interface-bound route. Silent link failures and node failures require detection that is coupled to removal of the affected forwarding state. Neighbor or liveness detection helps only when its result produces that state change; a neighbor becoming unreachable does not universally withdraw a static route.

Recovery has two prerequisites: the outer lookup must expose fallback, and the inner lookup must have a usable route. The destination routing protocol can converge before or after the programmed-path route disappears. Packets can be lost, reordered, or transiently looped during those changes.

Endpoints handle losses during convergence through transport recovery and path adaptation.

## Reachability and Restoration

Ordinary routing can use ECMP over surviving links and can return the decapsulated packet through a node already visited by the encapsulated packet. Forwarding uses the inner destination after decapsulation.

Delivery requires a usable route to the inner destination. All directions needed by the transport, including acknowledgments, require reachability independently.

When a more-specific route is restored, later packets prefer it again. This change can move traffic back to the programmed path and cause additional reordering. Previously decapsulated packets continue along ordinary routes.

# Example FRR/Linux Deployment

## Topology and Addressing

The reference configuration is `labs/fabric/srv6-mrc-local-fallback.xp` in the xform network-validation examples. It defines two leaves, two spines, and two clients. Each leaf connects to both spines; client1 attaches to leaf1 and client2 to leaf2.

| Role | Identifier or IPv6 prefix |
| ---- | ------------------------- |
| Common outer block and fallback prefix | `5f00::/32` |
| leaf1 local instruction | `5f00:0:200::/48` |
| leaf2 local instruction | `5f00:0:201::/48` |
| spine1 local instruction | `5f00:0:100::/48` |
| spine2 local instruction | `5f00:0:101::/48` |
| client1 LAN; client address | `5f00:0:301::/127`; `5f00:0:301::` |
| client2 LAN; client address | `5f00:0:302::/127`; `5f00:0:302::` |

The table shows the lab's address plan.

All four fabric nodes use FRR/Linux. Each has a local `/48` End instruction with NEXT-CSID, interface-bound static `/48` routes for its directly adjacent remote instructions, and a covering `/32` End.DT6 route selecting Linux table 254, the main IPv6 table. The leaves also have terminal `/128` End.DT6 entries at their locator base addresses. These terminal entries take precedence over the local `/48` and perform normal completion of the program.

OSPFv3 advertises client LANs rather than SRv6 locators. Thus the lab separates ordinary inner-destination reachability from the static programmed-path routes. The `/127` client routes are more specific than the covering `/32`, including after an inner lookup in the same table.

## Normal Forwarding

client1 selects either `5f00:0:200:100:201::` or `5f00:0:200:101:201::` as the outer destination. The inner destination remains client2, `5f00:0:302::`.

For the first program, forwarding proceeds as follows:

| Node | Outer destination on arrival | Processing |
| ---- | ---------------------------- | ---------- |
| leaf1 | `5f00:0:200:100:201::` | Local NEXT-CSID advances to `5f00:0:100:201::`; the remote `/48` selects spine1. |
| spine1 | `5f00:0:100:201::` | Local NEXT-CSID advances to `5f00:0:201::`; the remote `/48` selects leaf2. |
| leaf2 | `5f00:0:201::` | Terminal `/128` End.DT6 decapsulates; the connected client LAN route delivers the inner packet. |

The alternative program selects spine2. Reverse programs are `5f00:0:201:100:200::` and `5f00:0:201:101:200::`; their inner destination is client1, `5f00:0:301::`. The lab uses MRC traffic to exercise these programs.

## Local Fallback Examples

If leaf1 loses its link to spine1 and the corresponding remote `/48` is withdrawn, its local instruction can still advance the outer destination to `5f00:0:100:201::`. The following lookup matches the covering `/32`, decapsulates, and routes toward client2. Once ordinary routing has a usable surviving path, delivery can proceed through spine2 and leaf2.

If spine1 instead loses its link to leaf2, it advances the program to `5f00:0:201::`. After withdrawal of that remote `/48`, spine1 selects its covering route and decapsulates. Following OSPFv3 convergence, the inner packet can travel `spine1 -> leaf1 -> spine2 -> leaf2 -> client2`.

These forwarding outcomes depend on route withdrawal and destination-route convergence.

# Operational Considerations

**Provisioning.** Keep source programs, local instructions, programmed next hops, fallback coverage, and inner-destination routes consistent. A missing route can trigger early fallback even without a failure, masking a provisioning error. More-specific stale or discard entries can prevent fallback.

**Policy and isolation.** Fallback abandons the remaining path instructions. Use it only where ordinary routing satisfies the traffic's delivery and isolation policy. It is unsuitable for silently bypassing required service functions or mandatory waypoints. The lookup table associated with fallback must preserve tenant boundaries.

**MTU and diagnostics.** The illustrated encapsulation adds a 40-byte outer IPv6 header; additional headers require additional space. Configure packet sizes and path MTU handling for the encapsulated portion of the path. ICMP errors can refer to the outer packet before decapsulation and to the inner packet afterward; monitoring and endpoint processing must account for both.

**Transport behavior.** Fallback can change latency, ECMP selection, packet order, and congestion. A sender-selected program no longer identifies the physical path once fallback occurs. Transports should not assume that a path identifier proves traversal of the originally selected links.

**Observability.** Track programmed-route state, fallback counters, terminal decapsulation, inner lookup failures, and ordinary-routing convergence separately. Test both ingress-uplink and downstream-link withdrawal. Silent-failure tests must verify that the chosen detector actually removes the programmed route.

# Security Considerations

The SRv6 domain security considerations of {{RFC8986}} and {{RFC9800}} apply. A covering decapsulation prefix makes local processing available for more destinations than an individual terminal entry. Admission filtering must restrict who can send such packets into the domain and which inner destinations and lookup tables they can reach.

Apply source validation, destination access policy, and tenant isolation to the exposed packet. Ensure that local fallback cannot bypass controls normally applied at the intended egress or a programmed intermediate node.

Do not expose the covering behavior to untrusted external traffic. Invalid programs can deliberately reach it; fallback processing and subsequent lookups can also consume resources. Monitor unexpected fallback and enforce the domain's normal traffic and resource controls.

Because the example uses the same address block for outer instructions and client LANs, operators must preserve the more-specific client reachability and distinguish authorized encapsulated traffic from native traffic. End.DT6 validates the encapsulated packet before decapsulation.

# IANA Considerations

This document makes no request of IANA.

--- back
