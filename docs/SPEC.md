# Engineering Specification: p2p-anycast (`MeshCast`)

**Document Version:** 1.0.0-FINAL

**Status:** Ready for Implementation

**Target Runtimes:** Linux (AMD64, ARM64), macOS (Darwin-ARM64), Windows (AMD64)

**Primary Language:** Go (`1.24+`)

---

## 1. System Architecture & Core Invariants

`p2p-anycast` is a decentralized, user-space ingress overlay providing pseudo-Anycast routing, dynamic port forwarding, and multi-origin failover across uncoordinated public Edge VPS instances (e.g., Oracle Cloud Always Free compute) to private Origin servers behind NAT.

```text
[ Public Internet Clients ]
       │ (TCP / UDP Traffic)
       ▼
[ DNS: CNAME -> Geo/Round-Robin A Pool ]
   ├── Edge Node 1 (Public IP 1)
   ├── Edge Node 2 (Public IP 2)
   └── Edge Node 3 (Public IP 3)
       ▲
       │ Outbound Persistent mTLS QUIC Control & Data Plane
       │ (GossipSub Control + Ephemeral Streams + RFC 9221 Unreliable Datagrams)
       │
[ Origin Node(s) ] (Private LAN / NAT / Wire-Free)
   └── User-space Dispatch (Local Loopback / Unix Domain Sockets)

```

### Strict Architectural Invariants

1. **Zero Virtual Network Interfaces:** Do not create or manipulate OS-level virtual interfaces (`tun`/`tap`/`wg`). No root networking capabilities (`CAP_NET_ADMIN`) required.
2. **Outbound-Only Ingress to Origin:** Origins initiate outbound QUIC connections to public Edge IP endpoints. Edges never dial inbound into Origin network perimeters.
3. **No Head-of-Line Blocking for VoIP:** All UDP media (RTP) is transported via RFC 9221 QUIC Unreliable Datagram frames. Dropped packets must not trigger retransmissions.
4. **Opaque Edge-Side Routing:** Edges are unprivileged relays. They have zero knowledge of internal origin IP addresses, internal ports, or network topologies. Services are identified across the wire solely via deterministic 128-bit BLAKE3 `binding_id` tokens.
5. **Restricted L7 Inspection:** The only layer-7 peeking permitted on the edge is **TLS Server Name Indication (SNI)** parsing. Application-layer peeking for non-TLS protocols (HTTP host header, Minecraft handshake) is explicitly forbidden. Non-TLS services must bind distinct ports or rely on DNS SRV records.
6. **Tiered Hardware Root of Trust:** Node identities default to hardware crypto-coprocessors (TPM 2.0 / Apple Secure Enclave) before falling back to filesystem keys or ephemeral in-memory state.

---

## 2. Cryptographic Identity & PKI Specification

Because standard X.509 libraries do not natively support FIPS 204 ML-DSA-87 with arbitrary capability constraints, identity and authorization are governed via a **Post-Quantum Capability Manifest (PQ-CM)** over Protobuf.

### 2.1 Identity Hierarchy & Hardware Keystore Loader

Nodes must implement the standard Go `crypto.Signer` interface, loading their primary identity using a strict fallback waterfall:

1. **Tier 1A (Linux/Windows):** TPM 2.0 SRK (Storage Root Key) via `/dev/tpmrm0` or TBS.
2. **Tier 1B (macOS):** Apple Secure Enclave (`kSecAttrTokenIDSecureEnclave`).
3. **Tier 2:** Local encrypted filesystem key (`identity.key`).
4. **Tier 3:** Ephemeral key generated in volatile RAM.

Because current hardware chips only support classical curves (ECDSA P-256), the hardware key acts as the node's anchor, which is cross-bound to an ephemeral FIPS 204 ML-DSA-87 keypair generated on boot.

### 2.2 Protobuf Schema: `identity.proto`

```protobuf
syntax = "proto3";
package p2panycast.identity.v1;

enum NodeRole {
  ROLE_UNSPECIFIED = 0;
  EDGE_ROUTER = 1;
  ORIGIN_NODE = 2;
}

enum AuthorizedPolicy {
  POLICY_CLUSTERED_RTT = 0;
  POLICY_TLS_SNI = 1;
  POLICY_FAILOVER_STANDBY = 2;
  POLICY_STRICT_SINGLETON = 3;
}

message PortRange {
  uint32 start = 1;
  uint32 end = 2;
}

message ServiceCapability {
  string service_pattern = 1;                 // Wildcard glob: "pbx-*", "mc-smp"
  repeated AuthorizedPolicy allowed_policies = 2;
  repeated PortRange allowed_ports = 3;
}

message IdentityClaims {
  uint64 serial_number = 1;
  string issuer_id = 2;
  string subject_id = 3;
  NodeRole role = 4;
  bytes subject_mldsa_pubkey = 5;             // 2592 bytes (ML-DSA-87)
  string libp2p_peer_id = 6;                  // Base58-encoded Peer ID
  int64 not_before = 7;                       // Unix timestamp (seconds)
  int64 not_after = 8;                        // Unix timestamp (seconds)
  repeated ServiceCapability capabilities = 9;
}

message SignedCapabilityManifest {
  bytes claims_payload = 1;                   // Deterministic Protobuf bytes of IdentityClaims
  bytes ca_signature = 2;                     // 4627 bytes (ML-DSA-87 signature from Root CA)
  bytes ca_key_id = 3;                        // 32-byte SHA-256 hash of CA pubkey
}

```

### 2.3 Authentication Protocol (`/p2p-anycast/auth/1.0.0`)

Before GossipSub subscriptions or stream routing are allowed, the Origin and Edge authenticate over a dedicated, sequential libp2p stream:

```text
Dialing Node (Origin)                                    Listening Node (Edge)
      │                                                           │
      │── 1. AuthHello(NonceA [32B], ManifestA) ─────────────────►│
      │                                                           │ (Verify CA Sig,
      │                                                           │  Verify PeerID==SAN)
      │◄─ 2. AuthChallenge(NonceB [32B], ManifestB, SigA) ────────│
      │                                                           │
      │ (Verify CA Sig,                                           │
      │  Verify SigA over NonceA)                                 │
      │── 3. AuthComplete(SigB) ─────────────────────────────────►│
      │                                                           │ (Verify SigB over NonceB)
  [SECURED]                                                   [SECURED]

```

#### FIPS 204 Context Strings

To prevent cross-protocol signature replay, all ML-DSA-87 operations must enforce explicit context strings:

* **CA Signing Manifests:** `p2p-anycast:ca:manifest:v1`
* **Node Challenge Signatures:** `p2p-anycast:node:auth:v1`

---

## 3. Control Plane Specification (GossipSub Mesh)

All dynamic port allocations and route advertisements occur over the libp2p GossipSub topic `/p2p-anycast/registry/1.0.0`.

### 3.1 Protobuf Schema: `control.proto`

```protobuf
syntax = "proto3";
package p2panycast.control.v1;

enum TransportProtocol {
  PROTOCOL_UNSPECIFIED = 0;
  TCP = 1;
  UDP = 2;
  TCP_AND_UDP = 3;
}

enum RoutingPolicy {
  CLUSTERED_RTT = 0;      // RTT-optimized active/active across origins
  TLS_SNI = 1;            // Demux shared port via RFC 6066 SNI
  FAILOVER_STANDBY = 2;   // Primary/Backup promotion on lease timeout
  STRICT_SINGLETON = 3;   // Fails closed on origin loss. Absolutely NO fallback.
}

enum MessageType {
  ANNOUNCE = 0;
  HEARTBEAT = 1;
  REVOKE = 2;
}

message ServiceRegistration {
  MessageType type = 1;
  bytes binding_id = 2;           // 16-byte deterministic BLAKE3 token
  string service_id = 3;          // Human-readable identifier (e.g., "pbx-core")
  string origin_peer_id = 4;
  TransportProtocol protocol = 5;
  uint32 public_port = 6;         // Requested public port on the Edge
  RoutingPolicy policy = 7;
  
  string sni_hostname = 8;        // Required if policy == TLS_SNI
  uint32 lease_duration_sec = 9;  // Soft-state lease TTL (default: 60)
  uint64 lease_epoch = 10;        // Fencing token for STRICT_SINGLETON
  bool enable_proxy_protocol = 11;// TCP: Inject PROXYv2 binary header
  
  bytes origin_hmac_capability = 12; // 16-byte HMAC preventing token swapping
}

```

### 3.2 Deterministic `binding_id` Derivation

All origins contributing to a shared service independently compute the exact same 128-bit `binding_id` without cross-node synchronization:

$$\text{binding\_id} = \text{Truncate}_{128}\Big(\text{BLAKE3}\big(\text{service\_id} \parallel \text{protocol} \parallel \text{public\_port} \parallel \text{sni\_hostname}\big)\Big)$$

### 3.3 Connection-Scoped HMAC Capability Tokens

To prevent a compromised Edge router from routing traffic arriving on an authorized public port (e.g., 25565) into an unauthorized private service (e.g., 5060 VoIP), the Origin validates an HMAC:

$$\text{HMAC Capability} = \text{Truncate}_{128}\Big(\text{HMAC-SHA256}\big(K_{\text{origin}}, \text{EdgePeerID} \parallel \text{public\_port} \parallel \text{binding\_id}\big)\Big)$$

The Origin generates this token per Edge during registration. If an Edge forwards an envelope with mismatched parameters, the Origin drops the connection at $O(1)$ complexity.

---

## 4. Edge Router Ingress Specification (`anycast-edge`)

`anycast-edge` is deployed on public VPS nodes. It binds OS sockets dynamically and forwards packets over the persistent reverse QUIC tunnel.

```text
                     Edge Ingress Demuxer Pipeline
                     
 [ Public Client ]
         │
         ├─── TCP Connect (0.0.0.0:<Port>)
         │          │
         │          ▼
         │   [ Inspect Registry for Port ]
         │          │
         │          ├─► Policy == TLS_SNI ──────► Peek TLS ClientHello -> Extract SNI
         │          │                             Lookup binding_id by (Port, SNI)
         │          │
         │          └─► Policy == CLUSTERED_RTT ─► Select Origin by lowest libp2p Ping
         │                                        Lookup binding_id by Port
         │          │
         │          ▼
         │   Open libp2p Stream (/p2p-anycast/tcp/1.0.0)
         │   Write Preamble: [binding_id (16B) | hmac (16B)]
         │   (Optional: Write PROXYv2 Binary Header)
         │   Execute io.Copy bidirectional zero-copy pipe
         │
         └─── UDP Packet (0.0.0.0:<Port>)
                    │
                    ▼
             [ Inspect Registry for Port ]
                    │
                    ├─► STRICT_SINGLETON & Origin Down ──► DROP PACKET (Do not forward)
                    │
                    └─► Active Origin ──────────────────► Wrap in Datagram Envelope
                                                          Dispatch via quic.SendDatagram()

```

### 4.1 Zero-Allocation TLS SNI Peeker

The edge inspects only the first TLS ClientHello frame without completing the handshake:

1. Verify record byte `0x16` (Handshake) and TLS Major/Minor version (`0x03, 0x01..0x03`).
2. Read 16-bit record length; extract `ClientHello` handshake type (`0x01`).
3. Traverse the extension vector looking for `ExtensionType == 0x0000` (Server Name Indication).
4. Extract `ServerNameList[0]` hostname string.
5. If malformed or SNI is not found, emit TCP `RST` and abort.

---

## 5. Origin Egress Specification (`anycast-origin`)

`anycast-origin` runs alongside local workloads. It dials edges outbound, handles local dispatch, and maintains a user-space stateful NAT table for UDP return traffic.

### 5.1 Dynamic Dispatch Mapping

The Origin maintains an internal thread-safe map:


$$\text{local\_dispatch}: \text{binding\_id} \longrightarrow \text{TargetSocket} \ (\text{e.g., } \texttt{127.0.0.1:25565} \text{ or } \texttt{unix:///run/app.sock})$$

### 5.2 UDP Stateful Session Table (User-Space NAT)

Because incoming UDP datagrams are connectionless, return packets from local servers (e.g., Asterisk responding to SIP/RTP) must be routed back to the exact originating Edge and Client.

```text
             Inbound Packet Path                                Return Packet Path
             
 [ QUIC Datagram from Edge ]                          [ Local PBX Service: 5060 ]
              │                                                    │
              ▼                                                    ▼
   [ Parse Datagram Envelope ]                          [ Ephemeral Local Socket ]
   Extract: FlowID, ClientIP, Port                                 │
              │                                                    ▼
              ▼                                         [ Identify Session Record ]
   [ Session Lookup / Allocation ]                      Read Ephemeral Port -> Session
   Tuple: (EdgePeerID, ClientEndpoint)                             │
   Allocate: Ephemeral UDP Socket (127.0.0.1:0)                    ▼
              │                                         [ Wrap in Return Envelope ]
              ▼                                         Preamble: [FlowID (4B)]
   [ Forward to 127.0.0.1:<TargetPort> ]                           │
   Source Address == Ephemeral Socket                              ▼
                                                        [ Dispatch QUIC Datagram ]
                                                        Target == Originating EdgePeerID

```

#### The Datagram Envelope Framing (Binary Wire Format)

**Forward Path (Edge to Origin):**

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       binding_id (Bytes 0-3)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       binding_id (Bytes 4-7)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       binding_id (Bytes 8-11)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       binding_id (Bytes 12-15)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       hmac_token (Bytes 0-3)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       hmac_token (Bytes 4-7)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       hmac_token (Bytes 8-11)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       hmac_token (Bytes 12-15)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            flow_id                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                    client_ip (16 Bytes IPv6)                  +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          client_port          |          flags                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      raw_udp_payload ...                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```

**Return Path (Origin to Edge):**

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            flow_id                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      raw_udp_payload ...                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```

#### Session Eviction Algorithm

* Maintain active flows in a concurrent shard map (`sync.Map` or partitioned buckets).
* Refresh `last_seen_epoch` on each read/write.
* Run a timer goroutine every 5 seconds:
* **SIP Flow (Port 5060):** Evict after 60 seconds of inactivity.
* **RTP Flow (Ports 10000–20000):** Evict after 10 seconds of inactivity.
* On eviction, close the associated ephemeral `net.UDPConn` to release OS socket descriptors.



---

## 6. Routing Policy Matrix

| Policy | Clustered? | Failover Mechanics | Edge Action on Origin Loss | Primary Use Case |
| --- | --- | --- | --- | --- |
| `CLUSTERED_RTT` | **Yes** | Active/Active: Dynamic per-packet/stream reroute to lowest RTT peer. | Divert in-flight traffic to next best healthy Origin RTT. | Stateless HTTP, public game server lobbies, DNS. |
| `TLS_SNI` | **Yes** (by hostname) | Dedicated path per SNI string. | If specific SNI origin dies, emit TCP `RST`. Other SNIs unaffected. | Multi-tenant HTTPS, Secure WebSockets. |
| `FAILOVER_STANDBY` | **Yes** (1 Active, N Standby) | Active/Passive: Secondary promoted if primary misses 3 heartbeats. | Promote standby peer; flush stale TCP streams. | Stateful systems with external replication / shared block storage. |
| `STRICT_SINGLETON` | **NO** (Strictly 1) | **Fail-Closed:** Under no circumstances reroute traffic. | **Immediate Socket Drop:** Unbind port or send TCP `RST`/drop UDP. | **VoIP PBX (Asterisk/Kamailio)**, anti-split-brain state engines. |

---

## 7. Implementation Blueprint for Agents

Follow this phased checklist when generating the Go codebase:

### Phase 1: Cryptography & Identity Subsystem

* [ ] **Package:** `pkg/pki/mldsa`
* Implement FIPS 204 ML-DSA-87 key generation, signature, and verification with context strings.


* [ ] **Package:** `pkg/identity/keystore`
* Implement the hardware root-of-trust waterfall: TPM 2.0 SRK -> Apple Secure Enclave -> Filesystem -> In-Memory RAM.


* [ ] **Package:** `pkg/identity/manifest`
* Compile `identity.proto`. Implement manifest generation, canonical serialization, and signature validation functions.



### Phase 2: Transport & Authentication Handshake

* [ ] **Package:** `pkg/transport/quic`
* Configure `go-libp2p` using native QUIC transport (`libp2pquic.NewTransport`) configured with `quic.Config{EnableDatagrams: true}`.


* [ ] **Package:** `pkg/transport/auth`
* Implement the `/p2p-anycast/auth/1.0.0` protocol handler. Enforce mutual ML-DSA-87 challenge-response and bind verified claims to libp2p `peer.ID`.



### Phase 3: Control Plane & Dynamic Mesh

* [ ] **Package:** `pkg/control/protocol`
* Compile `control.proto`. Implement deterministic BLAKE3 `binding_id` derivation and HMAC capability generation.


* [ ] **Package:** `pkg/control/gossip`
* Implement GossipSub publisher and subscriber for `/p2p-anycast/registry/1.0.0`. Implement soft-state lease timers (60s lease, 20s heartbeat).



### Phase 4: Edge Router Daemon (`cmd/anycast-edge`)

* [ ] Implement in-memory registration table: `Port -> Policy -> Pool(PeerID, RTT, BindingID)`.
* [ ] Implement zero-allocation TLS SNI parser for TCP traffic.
* [ ] Implement dynamic OS socket listeners (`net.Listen`, `net.ListenUDP`).
* [ ] Implement TCP bidirectional stream pipe (`/p2p-anycast/tcp/1.0.0`) with PROXYv2 binary header synthesis.
* [ ] Implement UDP datagram forwarder wrapping incoming packets in the 36-byte framing header and calling `conn.SendDatagram()`.
* [ ] Implement `STRICT_SINGLETON` fail-closed socket drops.

### Phase 5: Origin Server Daemon (`cmd/anycast-origin`)

* [ ] Implement config parser mapping local target sockets (`127.0.0.1:PORT` or `/path/to/sock`) to service declarations.
* [ ] Implement outbound dialer maintaining persistent QUIC connections to all configured Edge multiaddrs.
* [ ] Implement stream receiver for `/p2p-anycast/tcp/1.0.0`, stripping the preamble and bridging data via `io.Copy` to local target sockets.
* [ ] Implement the User-Space UDP NAT session table:
* Ephemeral loopback socket pool.
* Symmetric return path dispatcher reading local replies, wrapping them in return datagram frames, and dispatching to the originating Edge.
* Sliding-window session reaper (10s RTP, 60s SIP).