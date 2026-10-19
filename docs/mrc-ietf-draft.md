---
title: "Selective uSID Advancement in SRv6 Fabrics"
abbrev: Selective uSID Advancement
docname: draft-vanbemmel-srv6-selective-usid-advancement-00
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

This document proposes selective uSID advancement for SRv6 fabrics. The transmitting NIC encodes a source-selected path and destination endpoint in the packet's existing IPv6 Destination Address. Ingress and destination leaves use ordinary IPv6 forwarding; intermediate spines and super-spines advance the encoded sequence. For paths that fit in the Destination Address, forwarding updates the address in place without adding an outer IPv6 header or a Segment Routing Header. The proposal separates endpoint path selection, leaf forwarding, and intermediate-node advancement.

--- middle

# Introduction

AI backend fabrics carry accelerator traffic whose throughput and completion time depend on congestion, loss, and path utilization. Multipath transports can select paths or distribute packets across them, but independent ECMP choices at successive stages can limit their control over the physical route.

Conventional SRv6 encapsulation adds an outer IPv6 header to carry the path. This design instead puts the path in the packet's existing IPv6 Destination Address and updates that address as the packet crosses the fabric. For paths that fit in that address, no outer IPv6 header or Segment Routing Header is added.

SRv6 network programming {{RFC8986}} and compressed SID encoding {{RFC9800}} provide the basis for expressing a path in an IPv6 Destination Address. This document uses *uSID* for a compressed SID using the NEXT-CSID flavor. The transmitting NIC selects the path, the leaves forward using ordinary IPv6 routing, and intermediate spines and super-spines advance the encoded sequence.

The related draft *SRv6 for Deterministic Path Placement in AI Backends* describes NIC-selected uSID programs using an outer IPv6 header and illustrates uSID processing at both leaves and spines {{I-D.filsfils-srv6ops-srv6-ai-backend}}. This proposal instead carries the path in the existing IPv6 Destination Address. The ingress leaf forwards toward the first spine without advancing the sequence; only intermediate fabric nodes advance it. The destination leaf forwards the packet to the receiving endpoint without decapsulation.

When the path fits in the Destination Address, this approach adds no header bytes and leaves packet length unchanged throughout the fabric. It avoids the bandwidth and MTU costs of encapsulation, requires no uSID-advancement capability at leaf switches, and allows the source to constrain path selection without relying on independent ECMP decisions at every stage.

# Forwarding Model

The NIC constructs a native IPv6 packet {{RFC8200}} containing the selected intermediate-node sequence and the target GPU node identifier in its Destination Address. The transport payload is carried directly by that packet. Each leaf performs an ordinary IPv6 lookup and preserves the Destination Address. An intermediate node matching its locally instantiated NEXT-CSID behavior advances the address and forwards according to the resulting destination.

Consider the path:

`NIC1 -> Leaf1 -> Spine5 -> Leaf3 -> GPU3-042`

The example uses a 32-bit common block `5f00:0000`, a 16-bit Spine5 uSID `0500`, a 16-bit routed-prefix identifier `0300` for GPU nodes behind Leaf3, and GPU3-042 identifier `0000:0000:0000:0042` in the remaining 64 bits.

NIC1 sends the packet with Destination Address:

`5f00:0000:0500:0300:0000:0000:0000:0042`

The table shows the Destination Address on arrival at each node and the action taken there. Spine5 performs the only address shift in this path.

| Node | Destination Address on arrival | Action |
| ---- | ------------------------------ | ------ |
| Leaf1 | `5f00:0000:0500:0300:0000:0000:0000:0042` | Match `5f00:0000:0500::/48`; forward to Spine5 with the address unchanged. |
| Spine5 | `5f00:0000:0500:0300:0000:0000:0000:0042` | Execute NEXT-CSID: shift the suffix after `0500` left by 16 bits and append 16 zero bits. Look up the resulting address and forward to Leaf3. |
| Leaf3 | `5f00:0000:0300:0000:0000:0000:0042:0000` | Route the terminal address to GPU3-042 with the address unchanged. |
| GPU3-042 | `5f00:0000:0300:0000:0000:0000:0042:0000` | Accept the terminal address and process the transport payload. |

The shift moves the entire suffix, including the GPU identifier. Thus, the initial suffix ending in `0042` becomes a terminal address ending in `0042:0000`. GPU3-042 accepts this address because it is assigned that exact terminal address; recognition of the identifier `0042` alone is not sufficient. Leaf3 has a route delivering the terminal address to GPU3-042. Neither Leaf3 nor the GPU reverses the shift or removes an encapsulating header.

# Addressing and Forwarding State

Every node on the selected path needs forwarding state appropriate to its role. The source encoding and that state must agree:

* Ingress leaves need routes toward the supported first-intermediate-node prefixes.
* Intermediate nodes need local NEXT-CSID instructions and onward forwarding state.
* Destination leaves need routes delivering terminal addresses to their intended GPU nodes, and receiving endpoints must accept those addresses.

These entries serve multiple flows without per-flow forwarding state. The installed next hops determine the physical links used, including any ECMP choices.

## Address Encoding

The source needs the common block, intermediate-node identifiers, relevant NEXT-CSID field widths, and a destination encoding that produces an address accepted by the receiving endpoint. An ingress-leaf instruction is unnecessary because the packet already arrives at that leaf; its route toward the first encoded intermediate node selects the uplink. The destination-leaf prefix is used for routing, not as an instruction executed by that leaf.

The address plan must accommodate both the selected intermediate sequence and the target GPU node identifier within 128 bits. Additional intermediate nodes consume address space and shift the destination encoding again. Identifier width depends on the space remaining after the path encoding. Programs of different lengths need destination encodings that account for their respective shifts; this draft leaves that allocation procedure open.

## Intermediate-Node Processing

NEXT-CSID processing follows Section 4.1 of {{RFC9800}}, which extends endpoint behaviors from {{RFC8986}}. It is distinct from ordinary IPv6 forwarding: an ingress leaf can match a prefix covering the active intermediate-node identifier without interpreting or changing the following address fields. Likewise, the destination leaf routes the terminal address without consuming it as a SID.

## Provisioning

An orchestrator, routing protocols, or another provisioning system supplies topology information and installs the required forwarding state. The choice of provisioning mechanism does not change the forwarding rules above. It must keep source encodings, intermediate-node behavior, destination-leaf routes, and endpoint address assignments consistent.

# Deployment Considerations

**Hybrid ECMP.** Deployments can encode selected stages and retain ECMP elsewhere. The source controls the encoded choices; ECMP selects links in the remaining portions. Data and probes follow the same physical route only when those ECMP decisions also agree.

**Failure handling.** Endpoints detect failed paths and select another usable program. Detection mechanisms and recovery timers belong to the deployed transport or monitoring system. Dynamic routing can restore reachability through a different physical route; deployments requiring stable path identity must keep path selection and forwarding state synchronized.

**Implementation requirements.** Intermediate devices must support the relevant NEXT-CSID behavior for native packets carrying the intended upper-layer protocol. Leaves need ordinary IPv6 forwarding and appropriate routes. The transmitting NIC must construct the program, and the receiving endpoint must accept the terminal address.

Implementations also need consistent endpoint addressing, transport connection identification across alternate programs, and diagnostic processing.

SRH considerations follow {{I-D.filsfils-srv6ops-srv6-ai-backend}}.

# Security Considerations

The SRv6 security considerations in {{RFC8986}} and {{RFC9800}} apply, together with the administrative-domain assumptions of {{I-D.filsfils-srv6ops-srv6-ai-backend}}. A source able to construct a program can influence both its intermediate path and receiving endpoint. Provisioning and admission policy need to constrain authorized sources, reachable programs, and terminal destinations.

Filtering must account for the address visible at each enforcement point: the initial path-encoded address or a subsequently advanced address. Tenant isolation and authorization must remain consistent across those observations. An encoded address is not evidence that a sender is authorized to use the selected path or contact the target GPU node.

# IANA Considerations

This document makes no request of IANA.

--- back
