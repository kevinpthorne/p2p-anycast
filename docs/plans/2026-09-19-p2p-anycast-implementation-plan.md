# Implementation Plan: p2p-anycast (`MeshCast`)

Implement **p2p-anycast** (`MeshCast`), a decentralized, user-space ingress overlay mesh providing pseudo-Anycast routing, dynamic port forwarding, and multi-origin failover across uncoordinated Edge VPS instances to private Origin servers behind NAT.

## User Review Required

> [!IMPORTANT]
> **Zero Virtual Interfaces & Pure User-Space**: All networking uses standard Go sockets (`net.Listen`, `net.ListenUDP`, `net.Dial`, Unix domain sockets). No `tun`/`tap` or `CAP_NET_ADMIN` capabilities will be used.
>
> **RFC 9221 QUIC Unreliable Datagrams**: SIP/RTP VoIP packets will never be sent over TCP-like reliable streams. They will use native QUIC datagrams over the persistent mTLS reverse tunnel.
>
> **Local Package Vendoring**: Per user request, all external Go dependencies (`circl`, `go-libp2p`, `blake3`, `go-tpm`, `quic-go`, `protobuf`) will be vendored into the local `vendor/` directory inside the repository to avoid cross-directory permission prompts and ensure isolated offline builds.
>
> **Static Route Table for Origin Forwarding**: Origin local dispatch supports a configurable static route table. Targets are not restricted to loopback; services can route to any arbitrary internal target endpoint, e.g. `minecraft.minecraft.svc.cluster.local:25565`, LAN IPs, or Unix domain sockets (`unix:///run/app.sock`).

## Proposed Architecture & Component Overview

```
[ Public Client ]
       │ (TCP / UDP)
       ▼
[ Edge Router (`anycast-edge`) ]
  ├── Dynamic Listener (0.0.0.0:<Port>)
  ├── TLS SNI Peeker (RFC 6066 zero-alloc ClientHello parsing)
  ├── PROXYv2 Injector (Binary client IP/port preservation)
  ├── UDP Datagram Forwarder (56-byte binary envelope -> QUIC Datagram)
  └── Routing Engine (CLUSTERED_RTT ping selector, STRICT_SINGLETON fail-closed)
       ▲
       │ Outbound Persistent Reverse QUIC Tunnel (mTLS + GossipSub)
       │ Handshake: /p2p-anycast/auth/1.0.0 (FIPS 204 ML-DSA-87)
       │ Control: /p2p-anycast/registry/1.0.0 (BLAKE3 binding_id + HMAC tokens)
       │ TCP Data: /p2p-anycast/tcp/1.0.0
       │ UDP Data: RFC 9221 Unreliable Datagrams
       │
[ Origin Sidecar (`anycast-origin`) ]
  ├── Outbound QUIC Dialer (Connects out to Edges; never listens publicly)
  ├── Local Socket Dispatcher & Static Route Table (Target: host:port, cluster DNS FQDN e.g. minecraft.minecraft.svc.cluster.local:25565, or unix://)
  └── Stateful User-Space UDP NAT Table:
      ├── Ephemeral UDP Socket Pool (Dynamic source port allocation)
      ├── Symmetric Return Path Dispatcher (FlowID 4B return envelope -> Edge)
      └── Sliding-Window Session Reaper (10s RTP, 60s SIP)
```

---

## Proposed Changes

### 1. Project Initialization & Vendoring

#### [NEW] `go.mod`
- Module `p2p-anycast` with Go 1.25.
- Dependencies:
  - `github.com/cloudflare/circl` (v1.6.3 for FIPS 204 ML-DSA-87)
  - `lukechampine.com/blake3` (v1.4.1 for binding ID)
  - `github.com/google/go-tpm` (v0.9.8 for TPM2 SRK probe)
  - `github.com/libp2p/go-libp2p` (v0.48.0 for QUIC transport and host)
  - `github.com/libp2p/go-libp2p-pubsub` (v0.10.0 for GossipSub)
  - `github.com/quic-go/quic-go` (v0.55.0 for RFC 9221 datagrams)
  - `google.golang.org/protobuf` (v1.36.11 for protobuf serialization)
- Run `go mod tidy` and `go mod vendor` to populate the workspace `vendor/` tree.

#### [NEW] `Makefile`
- Standard build, test, clean, vendor, and CA CLI targets.

---

### 2. Protocol Buffers & Generated Types

#### [NEW] `proto/identity.proto`
- `NodeRole`: `EDGE_ROUTER`, `ORIGIN_NODE`.
- `AuthorizedPolicy`: `POLICY_CLUSTERED_RTT`, `POLICY_TLS_SNI`, `POLICY_FAILOVER_STANDBY`, `POLICY_STRICT_SINGLETON`.
- `PortRange`: `start`, `end`.
- `ServiceCapability`: `service_pattern`, `allowed_policies`, `allowed_ports`.
- `IdentityClaims`: `serial_number`, `issuer_id`, `subject_id`, `role`, `subject_mldsa_pubkey` (2592B), `libp2p_peer_id`, `not_before`, `not_after`, `capabilities`.
- `SignedCapabilityManifest`: `claims_payload` (deterministic bytes), `ca_signature` (4627B), `ca_key_id` (32B).
- `AuthHello`, `AuthChallenge`, `AuthComplete` messages for `/p2p-anycast/auth/1.0.0`.

#### [NEW] `proto/control.proto`
- `TransportProtocol`: `TCP`, `UDP`, `TCP_AND_UDP`.
- `RoutingPolicy`: `CLUSTERED_RTT`, `TLS_SNI`, `FAILOVER_STANDBY`, `STRICT_SINGLETON`.
- `MessageType`: `ANNOUNCE`, `HEARTBEAT`, `REVOKE`.
- `ServiceRegistration`: `type`, `binding_id` (16B), `service_id`, `origin_peer_id`, `protocol`, `public_port`, `policy`, `sni_hostname`, `lease_duration_sec`, `lease_epoch`, `enable_proxy_protocol`, `origin_hmac_capability` (16B).

#### [NEW] `pkg/proto/identity/identity.pb.go` & `pkg/proto/control/control.pb.go`
- Generated Go protobuf implementations with deterministic serialization support.

---

### 3. Cryptographic Identity & PKI Subsystem

#### [NEW] `pkg/pki/mldsa/mldsa.go`
- ML-DSA-87 (FIPS 204) wrapper using `github.com/cloudflare/circl/sign/mldsa/mldsa87`.
- Constants:
  - `ContextCAManifest = "p2p-anycast:ca:manifest:v1"`
  - `ContextNodeAuth   = "p2p-anycast:node:auth:v1"`
  - `PublicKeySize     = 2592`
  - `PrivateKeySize    = 4896`
  - `SignatureSize     = 4627`
- Enforce explicit context strings for domain separation.
- Key generation, PEM encoding/decoding, signing, and verification helpers.

#### [NEW] `pkg/pki/keystore/keystore.go`
- Hardware `crypto.Signer` keystore fallback waterfall:
  1. **Tier 1A (TPM 2.0)**: Probe `/dev/tpmrm0` / `/dev/tpm0` using `go-tpm`.
  2. **Tier 1B (Apple Secure Enclave)**: Probe macOS Secure Enclave (`kSecAttrTokenIDSecureEnclave`).
  3. **Tier 2 (Filesystem)**: Load or persist `identity.key`.
  4. **Tier 3 (RAM)**: Ephemeral volatile in-memory key.
- Hardware anchor cross-binding to ephemeral ML-DSA-87 keypair.
- Derives corresponding libp2p `crypto.PrivKey` and `peer.ID`.

#### [NEW] `pkg/pki/manifest/manifest.go`
- Canonical deterministic serialization: `proto.MarshalOptions{Deterministic: true}`.
- Manifest signing with CA ML-DSA-87 private key under `p2p-anycast:ca:manifest:v1`.
- Manifest verification against Root CA public key and validity period (`not_before` / `not_after`).
- Capability matching: glob pattern verification (`service_pattern`), port range checking, policy verification.

---

### 4. Transport & Dynamic Mesh Handshake

#### [NEW] `pkg/transport/quic/transport.go`
- Helper configuring `go-libp2p` host with native QUIC transport and `quic.Config{EnableDatagrams: true}`.
- Connection unwrapper using `network.Conn.As(&quicConn)` to extract the raw `*quic.Conn` for RFC 9221 datagram send/receive.

#### [NEW] `pkg/transport/auth/auth.go`
- Protocol handler for `/p2p-anycast/auth/1.0.0`:
  1. Origin sends `AuthHello(NonceA [32B], ManifestA)`.
  2. Edge verifies ManifestA CA signature, checks `claims.libp2p_peer_id == remotePeer.ID`, role == ORIGIN_NODE.
  3. Edge generates `NonceB [32B]`, signs `NonceA` with Edge ML-DSA-87 under `p2p-anycast:node:auth:v1`, replies with `AuthChallenge(NonceB, ManifestB, SigA)`.
  4. Origin verifies ManifestB CA signature, checks `claims.libp2p_peer_id == remotePeer.ID`, role == EDGE_ROUTER, verifies `SigA` over `NonceA`.
  5. Origin signs `NonceB` with Origin ML-DSA-87 under `p2p-anycast:node:auth:v1`, replies with `AuthComplete(SigB)`.
  6. Edge verifies `SigB` over `NonceB`. If valid, marks peer authenticated and registers verified capabilities.

---

### 5. Control Plane: GossipSub, BLAKE3, HMAC, & Leases

#### [NEW] `pkg/control/binding/binding.go`
- Deterministic 128-bit `binding_id` calculation:
  $$\text{binding\_id} = \text{Truncate}_{128}\Big(\text{BLAKE3}\big(\text{service\_id} \parallel \text{protocol} \parallel \text{public\_port} \parallel \text{sni\_hostname}\big)\Big)$$
- Connection-scoped HMAC capability calculation and verification:
  $$\text{HMAC Capability} = \text{Truncate}_{128}\Big(\text{HMAC-SHA256}\big(K_{\text{origin}}, \text{EdgePeerID} \parallel \text{public\_port} \parallel \text{binding\_id}\big)\Big)$$

#### [NEW] `pkg/control/lease/lease.go`
- Soft-state lease tracker:
  - 60s lease TTL, 20s heartbeat intervals.
  - Eviction after 3 missed heartbeats or on immediate libp2p peer disconnect.
  - Monotonic `lease_epoch` fencing for `STRICT_SINGLETON`.
  - Notification callbacks on service addition, update, and eviction.

#### [NEW] `pkg/control/gossip/gossip.go`
- Libp2p GossipSub publisher and subscriber for `/p2p-anycast/registry/1.0.0`.
- Automatic deserialization, capability manifest validation, and dispatch to lease manager.

---

### 6. Edge Router Ingress (`pkg/edge/`, `cmd/anycast-edge/`)

#### [NEW] `pkg/edge/sni/sni.go`
- Zero-allocation RFC 6066 TLS SNI parser.
- Inspects TLS record header (`0x16`, `0x03, 0x01..0x03`, length), validates `ClientHello` (`0x01`), skips session ID, cipher suites, compression methods, walks extension block to `0x0000` (SNI), extracts server hostname.
- Emits TCP RST on invalid/missing SNI.

#### [NEW] `pkg/edge/proxy/proxy.go`
- PROXYv2 binary header synthesis:
  - 12-byte v2 signature `\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A`.
  - Protocol command `0x21` (PROXY), address family `0x11` (IPv4 TCP) or `0x21` (IPv6 TCP).
  - Writes client source IP/port and edge destination IP/port.
- Bi-directional stream piping:
  - Opens `/p2p-anycast/tcp/1.0.0` to target origin.
  - Writes 32-byte preamble `[binding_id (16B) | hmac_token (16B)]`.
  - Injects PROXYv2 header if `enable_proxy_protocol == true`.
  - Flushes peeked ClientHello bytes, then zero-copy `io.Copy` bidirectional pipe.

#### [NEW] `pkg/edge/forwarder/forwarder.go`
- UDP datagram forwarding over RFC 9221 QUIC Datagrams:
  - Forward envelope (56B header + raw payload):
    `[binding_id (16B) | hmac_token (16B) | flow_id (4B) | client_ip (16B IPv6/mapped IPv4) | client_port (2B) | flags (2B) | raw_payload]`
  - Dispatches via `quic.Connection.SendDatagram()`.
  - Return path: receives datagrams `[flow_id (4B) | raw_payload]`, demuxes using flow table to original client UDP endpoint, writes via public socket.

#### [NEW] `pkg/edge/ingress/ingress.go`
- Dynamic listener manager for OS sockets (`net.Listen`, `net.ListenUDP`):
  - Binds public ports when authorized origin registers.
  - Closes socket or drops packets when all origins expire or on `STRICT_SINGLETON` fail-closed.
  - Routes traffic according to policy:
    - `CLUSTERED_RTT`: Pings active origins, picks lowest RTT peer.
    - `TLS_SNI`: Peeks SNI, routes to matching origin.
    - `FAILOVER_STANDBY`: Routes to active primary, promotes standby on failure.
    - `STRICT_SINGLETON`: Routes to single origin; if disconnected, drops socket immediately.

#### [NEW] `cmd/anycast-edge/main.go`
- Edge daemon CLI entrypoint, loading configuration, hardware keystore, libp2p host, GossipSub, and starting the ingress engine.

---

### 7. Origin Daemon (`pkg/origin/`, `cmd/anycast-origin/`)

#### [NEW] `pkg/origin/dispatch/dispatch.go`
- Thread-safe static route table mapping `binding_id` to target endpoints:
  - Supports network endpoints: `host:port` (e.g. `minecraft.minecraft.svc.cluster.local:25565`, `127.0.0.1:25565`) and Unix domain sockets (`unix:///run/app.sock`).
  - Implements route registration: `AddRoute(bindingID [16]byte, target string, protocol TransportProtocol)`.
  - Resolves target addresses dynamically (`net.ResolveTCPAddr`, `net.ResolveUDPAddr`).

#### [NEW] `pkg/origin/dialer/dialer.go`
- Outbound persistent QUIC dialer to configured Edge multiaddrs.
- Auto-reconnect with exponential backoff on connection drops.
- Performs `/p2p-anycast/auth/1.0.0` handshake upon connection.
- Heartbeat loop: publishes `HEARTBEAT` every 20 seconds.

#### [NEW] `pkg/origin/stream/stream.go`
- Handler for `/p2p-anycast/tcp/1.0.0`:
  - Reads 32-byte preamble: `[binding_id (16B) | hmac_token (16B)]`.
  - Verifies HMAC token using $K_{\text{origin}}$.
  - Resolves target socket by `binding_id` from the static route table.
  - Connects to target endpoint (`net.Dial("tcp", target)` or `net.Dial("unix", path)`), resolving cluster FQDNs or IP addresses.
  - Pipes data bi-directionally between libp2p stream and target service.

#### [NEW] `pkg/origin/nat/nat.go`
- Stateful user-space UDP NAT table:
  - Maps `(EdgePeerID, FlowID, ClientEndpoint)` -> Ephemeral socket (`net.ListenUDP("udp", &net.UDPAddr{Port: 0})`).
  - Resolves target backend address from static route table (e.g. `127.0.0.1:5060` or `sip.voice.svc.cluster.local:5060`).
  - Forwards incoming datagram payload from ephemeral socket to backend service.
  - Ephemeral socket goroutine captures return packets from backend, wraps in return envelope `[flow_id (4B) | raw_payload]`, and sends via `quic.Connection.SendDatagram()` back to originating Edge.
  - Sliding-window reaper running every 5 seconds:
    - SIP (port 5060): evicts idle flows after 60s.
    - RTP (ports 10000–20000): evicts idle flows after 10s.
    - Closes ephemeral OS socket on eviction.

#### [NEW] `cmd/anycast-origin/main.go`
- Origin daemon CLI entrypoint, loading configuration (defining services and their static route targets), keystore, dialing Edges, and managing local service dispatch.

---

### 8. CA CLI Utility (`cmd/anycast-ca/`)

#### [NEW] `cmd/anycast-ca/main.go`
- Subcommands:
  - `anycast-ca init`: Generates Root ML-DSA-87 keypair (`ca.priv`, `ca.pub`).
  - `anycast-ca sign`: Reads JSON policy, generates `IdentityClaims`, signs with `ca.priv` under `p2p-anycast:ca:manifest:v1`, outputs `manifest.pb`.
  - `anycast-ca inspect`: Decodes and validates `manifest.pb`, displaying claims, validity period, and verifying signature against `ca.pub`.

---

### 9. Test Suite (`test/`)

#### [NEW] `test/test_helpers.go`
- Mock TCP echo server, mock TLS echo server (with TLS certificate for SNI testing), and mock UDP echo server.
- CA and key generation helpers for integration testing.

#### [NEW] `test/e2e_tcp_test.go`
- End-to-end test for TCP proxying and TLS SNI demuxing:
  - Spins up TLS echo server for `service1.internal` and `service2.internal`.
  - Starts Origin advertising `TLS_SNI` for both hostnames on shared public port.
  - Starts Edge router.
  - Public TLS client connects to Edge, verifies SNI demuxing and bidirectional echo.
  - Verifies PROXYv2 header decoding.

#### [NEW] `test/e2e_udp_test.go`
- End-to-end test for symmetric UDP NAT & VoIP datagrams:
  - Spins up UDP echo server on localhost:5060 and localhost:10002.
  - Starts Origin advertising UDP service.
  - Multiple simulated public clients stream UDP datagrams to Edge.
  - Verifies RFC 9221 datagram transmission, ephemeral socket allocation, demuxing of return packets to correct clients, and sliding-window flow reaping.

#### [NEW] `test/strict_singleton_test.go`
- Verifies `STRICT_SINGLETON` fail-closed behavior:
  - Starts Edge and Origin with `STRICT_SINGLETON` policy.
  - Verifies public listener is bound and traffic flows.
  - Stops Origin.
  - Verifies Edge immediately drops socket/connections and drops incoming UDP packets without rerouting to any standby node.

---

## Verification Plan

### Automated Tests
1. **Unit tests**:
   ```bash
   go test -v -race ./pkg/pki/... ./pkg/control/... ./pkg/edge/... ./pkg/origin/...
   ```
2. **Integration tests**:
   ```bash
   go test -v -race -timeout 120s ./test/...
   ```
3. **Build verification**:
   ```bash
   go build -v ./cmd/...
   ```
4. **Code Quality**:
   ```bash
   go vet ./...
   ```
