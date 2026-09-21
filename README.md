# p2p-anycast (`MeshCast`)

[![Go Version](https://img.shields.io/badge/go-1.24%2B-blue.svg)](https://golang.org)
[![Post-Quantum PKI](https://img.shields.io/badge/pki-FIPS%20204%20ML--DSA--87-success.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![QUIC Datagrams](https://img.shields.io/badge/transport-RFC%209221%20Datagrams-orange.svg)](https://datatracker.ietf.org/doc/html/rfc9221)
[![Pure User-Space](https://img.shields.io/badge/networking-pure%20user--space-lightgrey.svg)](#core-architectural-invariants)

**MeshCast (`p2p-anycast`)** is a decentralized, pure user-space ingress overlay mesh providing pseudo-Anycast routing, dynamic port forwarding, and multi-origin failover across uncoordinated public Edge VPS instances to private Origin servers operating behind NAT perimeters.

---

## Table of Contents

- [Core Architectural Invariants](#core-architectural-invariants)
- [Architecture Overview](#architecture-overview)
- [Routing Policy Matrix](#routing-policy-matrix)
- [Binary Wire Formats](#binary-wire-formats)
  - [Forward Datagram Envelope (Edge to Origin)](#forward-datagram-envelope-edge-to-origin)
  - [Return Datagram Envelope (Origin to Edge)](#return-datagram-envelope-origin-to-edge)
  - [TCP Stream Preamble & PROXYv2](#tcp-stream-preamble--proxyv2)
- [Repository Structure](#repository-structure)
- [Building from Source](#building-from-source)
- [Quickstart Guide](#quickstart-guide)
  - [1. Initialize Root CA](#1-initialize-root-ca)
  - [2. Generate Node Manifests](#2-generate-node-manifests)
  - [3. Start the Edge Router](#3-start-the-edge-router)
  - [4. Start the Origin Sidecar](#4-start-the-origin-sidecar)
- [Testing & Verification](#testing--verification)

---

## Core Architectural Invariants

The design enforces strict constraints that guarantee portability, zero privilege requirements, and optimal performance for real-time media:

1. **Pure User-Space Networking:** No virtual network interfaces (`tun`/`tap`/`wg0`) or elevated Linux capabilities (`CAP_NET_ADMIN`) required. All operations run over standard user-space OS sockets (`net.Listen`, `net.ListenUDP`, `net.Dial`, Unix domain sockets).
2. **Outbound-Only Ingress to Origin:** Private origins live behind NAT and firewall barriers and never listen for incoming mesh connections. Origins establish outbound persistent mTLS QUIC tunnels to public Edge VPS nodes.
3. **Zero Head-of-Line Blocking for VoIP:** All UDP media (SIP & RTP) is transported strictly over **RFC 9221 QUIC Unreliable Datagrams** (`quic.Connection.SendDatagram`). Raw UDP packets are never multiplexed over reliable TCP-like streams.
4. **Opaque Edge-Side Routing:** Edges have zero knowledge of internal origin IPs, internal ports, or network topologies. Services are identified across the wire solely via deterministic 128-bit BLAKE3 `binding_id` tokens and connection-scoped HMAC capability tokens.
5. **TLS SNI Peeking Only:** Layer-7 peeking on the Edge is strictly restricted to parsing RFC 6066 TLS Server Name Indication (SNI) from ClientHello headers. Non-TLS services must bind distinct ports or rely on DNS SRV records.
6. **Post-Quantum PKI (ML-DSA-87):** Enforces FIPS 204 ML-DSA-87 for all node identity signing, capability manifests, and handshake challenges, utilizing explicit domain-separated context strings:
   - `p2p-anycast:ca:manifest:v1` for Root CA manifest signing.
   - `p2p-anycast:node:auth:v1` for runtime challenge-response handshakes.
7. **Tiered Hardware Keystore:** Node cryptographic identities implement `crypto.Signer` and follow a strict waterfall:
   $$\text{TPM 2.0} \longrightarrow \text{Apple Secure Enclave} \longrightarrow \text{Filesystem Key} \longrightarrow \text{RAM}$$
   The hardware anchor cross-binds to an ephemeral ML-DSA-87 keypair and libp2p Peer ID on boot.
8. **Static Route Table with Cluster FQDN Support:** The Origin sidecar maintains a static route table that resolves target endpoints dynamically, supporting localhost (`127.0.0.1:port`), Unix domain sockets (`unix:///run/app.sock`), and internal Kubernetes/cluster DNS FQDNs (e.g. `minecraft.minecraft.svc.cluster.local:25565`).

---

## Architecture Overview

```text
[ Public Internet Clients ]
       │ (TCP / UDP Traffic)
       ▼
[ Edge Router (`anycast-edge`) ] (Runs on public VPS)
  ├── Dynamic Listener (0.0.0.0:<Port>)
  ├── TLS SNI Peeker (RFC 6066 zero-alloc ClientHello parsing)
  ├── PROXYv2 Injector (Binary client IP/port preservation)
  ├── UDP Datagram Forwarder (56-byte envelope -> RFC 9221 QUIC Datagram)
  └── Routing Engine (CLUSTERED_RTT ping selector, STRICT_SINGLETON fail-closed)
       ▲
       │ Outbound Persistent Reverse QUIC Tunnel (mTLS + GossipSub)
       │ Handshake: /p2p-anycast/auth/1.0.0 (FIPS 204 ML-DSA-87)
       │ Control:   /p2p-anycast/registry/1.0.0 (BLAKE3 binding_id + HMAC tokens)
       │ TCP Data:  /p2p-anycast/tcp/1.0.0
       │ UDP Data:  RFC 9221 Unreliable Datagrams
       │
[ Origin Sidecar (`anycast-origin`) ] (Runs next to local workloads)
  ├── Outbound QUIC Dialer (Connects out to Edges; never listens publicly)
  ├── Local Socket Dispatcher & Static Route Table (Target: host:port, cluster FQDN, or unix://)
  └── Stateful User-Space UDP NAT Table:
      ├── Ephemeral UDP Loopback Socket Pool (Dynamic source port allocation)
      ├── Symmetric Return Path Dispatcher (FlowID 4B return envelope -> Edge)
      └── Sliding-Window Session Reaper (10s RTP, 60s SIP)
```

---

## Routing Policy Matrix

| Policy | Clustered? | Failover Mechanics | Edge Action on Origin Loss | Primary Use Case |
| :--- | :---: | :--- | :--- | :--- |
| `CLUSTERED_RTT` | **Yes** | Active/Active: Dynamic per-packet/stream reroute to lowest RTT peer. | Diverts in-flight traffic to next best healthy Origin RTT. | Stateless HTTP, game server lobbies, DNS. |
| `TLS_SNI` | **Yes** (by hostname) | Dedicated path per SNI string on a shared public port. | If specific SNI origin dies, emit TCP `RST`. Other SNIs unaffected. | Multi-tenant HTTPS, Secure WebSockets. |
| `FAILOVER_STANDBY` | **Yes** (1 Active, N Standby) | Active/Passive: Secondary promoted if primary misses 3 heartbeats. | Promotes standby peer; flushes stale TCP streams. | Stateful systems with external replication / shared storage. |
| `STRICT_SINGLETON` | **NO** (Strictly 1) | **Fail-Closed:** Under no circumstances reroute traffic. | **Immediate Socket Drop:** Closes listener or sends TCP `RST` / drops UDP. | **VoIP PBX (Asterisk/Kamailio)**, anti-split-brain state engines. |

---

## Binary Wire Formats

### Forward Datagram Envelope (Edge to Origin)

Incoming UDP media packets arriving on the Edge are encapsulated into a 56-byte binary forward envelope before transmission over QUIC:

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

### Return Datagram Envelope (Origin to Edge)

Replies captured by the Origin's stateful UDP NAT table from the local backend service are prefixed with the 4-byte `flow_id` and dispatched back to the originating Edge:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            flow_id                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      raw_udp_payload ...                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### TCP Stream Preamble & PROXYv2

When an Edge opens a TCP proxy stream (`/p2p-anycast/tcp/1.0.0`) to an Origin:
1. **Preamble (32 Bytes):** `[binding_id (16B) | hmac_token (16B)]`.
2. **PROXYv2 (Optional):** Injects a binary PROXYv2 header preserving real client IP and port.
3. **Payload:** Flushes peeked ClientHello bytes followed by bidirectional zero-copy `io.Copy`.

---

## Repository Structure

```text
p2p-anycast/
├── cmd/
│   ├── anycast-ca/       # CLI to generate Root CA, sign manifests, inspect tokens
│   ├── anycast-edge/     # Edge router daemon (runs on public VPS)
│   └── anycast-origin/   # Origin sidecar daemon (runs alongside local services)
├── pkg/
│   ├── pki/
│   │   ├── mldsa/        # FIPS 204 ML-DSA-87 wrapper with context string support
│   │   ├── keystore/     # Hardware crypto.Signer loader (TPM2, Secure Enclave, File, RAM)
│   │   └── manifest/     # Canonical Protobuf serialization, signing, and verification
│   ├── proto/
│   │   ├── identity/     # Generated Protobuf Go code for identity.proto
│   │   └── control/      # Generated Protobuf Go code for control.proto
│   ├── transport/
│   │   ├── quic/         # go-libp2p QUIC transport configured with EnableDatagrams: true
│   │   └── auth/         # /p2p-anycast/auth/1.0.0 challenge-response protocol stream
│   ├── control/
│   │   ├── gossip/       # libp2p GossipSub publisher/subscriber on /p2p-anycast/registry/1.0.0
│   │   ├── lease/        # Soft-state lease tracking (60s TTL, 20s heartbeats, fencing epochs)
│   │   └── binding/      # BLAKE3 binding_id derivation and HMAC capability generation
│   ├── edge/
│   │   ├── ingress/      # Dynamic net.Listen / net.ListenUDP management
│   │   ├── sni/          # Zero-allocation non-terminating TLS SNI peeker
│   │   ├── proxy/        # TCP stream piping with PROXYv2 binary header injection
│   │   └── forwarder/    # UDP datagram framing and quic-go Datagram dispatch
│   └── origin/
│       ├── dialer/       # Outbound persistent QUIC dialer to Edge multiaddrs
│       ├── dispatch/     # Static route table supporting hostnames, cluster DNS, & Unix sockets
│       └── nat/          # Stateful user-space UDP NAT table, ephemeral socket pool, and reaper
├── proto/
│   ├── identity.proto    # Post-quantum capability manifest schema
│   └── control.proto     # Dynamic port registration & routing policy schema
├── test/
│   ├── e2e_tcp_test.go   # End-to-end test verifying TCP proxying + TLS SNI demuxing
│   ├── e2e_udp_test.go   # End-to-end test verifying symmetric UDP NAT & VoIP datagrams
│   ├── strict_singleton_test.go # Test verifying strict singleton fail-closed behavior
│   └── test_helpers.go   # Mock upstream servers (echo TCP/UDP, TLS echo)
├── vendor/               # Fully vendored local Go module dependencies
├── Makefile
├── go.mod
└── go.sum
```

---

## Building from Source

Prerequisites: **Go 1.24+** (tested on Go 1.25+).

```bash
# Build all CLI binaries into bin/
make build

# Or build individually:
go build -o bin/anycast-ca ./cmd/anycast-ca
go build -o bin/anycast-edge ./cmd/anycast-edge
go build -o bin/anycast-origin ./cmd/anycast-origin
```

---

## Quickstart Guide

### 1. Initialize Root CA

Generate a post-quantum Root CA keypair (`ca.priv`, `ca.pub`):

```bash
./bin/anycast-ca init --out-dir .
```

Output:
```text
Successfully generated Root CA ML-DSA-87 keypair:
  Private Key: ./ca.priv
  Public Key:  ./ca.pub
  CA Key ID:   <sha256-hex>
```

### 2. Generate Node Manifests

#### Edge Router Policy (`edge_policy.json`)

```json
{
  "serial_number": 1,
  "subject_id": "edge-us-east-01",
  "role": "EDGE_ROUTER",
  "libp2p_peer_id": "12D3KooWEdgePeerID...",
  "subject_mldsa_pubkey_file": "edge.pub",
  "validity_days": 365,
  "capabilities": []
}
```

Sign the Edge manifest:
```bash
./bin/anycast-ca sign \
  --ca-priv ca.priv \
  --ca-pub ca.pub \
  --policy edge_policy.json \
  --out edge_manifest.pb
```

#### Origin Node Policy (`origin_policy.json`)

```json
{
  "serial_number": 2,
  "subject_id": "origin-pbx-01",
  "role": "ORIGIN_NODE",
  "libp2p_peer_id": "12D3KooWOriginPeerID...",
  "subject_mldsa_pubkey_file": "origin.pub",
  "validity_days": 365,
  "capabilities": [
    {
      "service_pattern": "pbx-*",
      "allowed_policies": ["STRICT_SINGLETON", "CLUSTERED_RTT"],
      "allowed_ports": [
        {"start": 5060, "end": 5060},
        {"start": 10000, "end": 20000}
      ]
    },
    {
      "service_pattern": "minecraft-*",
      "allowed_policies": ["STRICT_SINGLETON"],
      "allowed_ports": [
        {"start": 25565, "end": 25565}
      ]
    }
  ]
}
```

Sign the Origin manifest:
```bash
./bin/anycast-ca sign \
  --ca-priv ca.priv \
  --ca-pub ca.pub \
  --policy origin_policy.json \
  --out origin_manifest.pb
```

Inspect any manifest:
```bash
./bin/anycast-ca inspect --manifest origin_manifest.pb --ca-pub ca.pub
```

### 3. Start the Edge Router

Deploy `anycast-edge` on your public VPS node:

```bash
./bin/anycast-edge \
  --listen-p2p "/ip4/0.0.0.0/udp/9090/quic-v1" \
  --manifest edge_manifest.pb \
  --ca-pub ca.pub \
  --identity-key identity.key
```

### 4. Start the Origin Sidecar

Create `origin_config.json`:

```json
{
  "edge_multiaddrs": [
    "/ip4/203.0.113.10/udp/9090/quic-v1/p2p/12D3KooWEdgePeerID..."
  ],
  "origin_master_key": "4f8a3c10b7e289d04f8a3c10b7e289d04f8a3c10b7e289d04f8a3c10b7e289d0",
  "services": [
    {
      "service_id": "pbx-sip",
      "protocol": "UDP",
      "public_port": 5060,
      "policy": "STRICT_SINGLETON",
      "target": "127.0.0.1:5060"
    },
    {
      "service_id": "minecraft-smp",
      "protocol": "TCP",
      "public_port": 25565,
      "policy": "STRICT_SINGLETON",
      "target": "minecraft.minecraft.svc.cluster.local:25565"
    }
  ]
}
```

Run `anycast-origin`:

```bash
./bin/anycast-origin \
  --config origin_config.json \
  --manifest origin_manifest.pb \
  --ca-pub ca.pub \
  --identity-key identity.key
```

---

## Nix & NixOS Deployment

The repository provides a complete Nix flake (`flake.nix`) and declarative NixOS modules (`nix/modules/`).

### 1. Building & Running with Nix Flakes

Build the binaries hermetically using Nix:

```bash
# Build binaries
nix build .#anycast-edge
nix build .#anycast-origin
nix build .#anycast-ca

# Or run directly via Nix
nix run .#anycast-edge -- --help
nix run .#anycast-origin -- --help
```

### 2. NixOS Service Modules

Add `p2p-anycast` to your system configuration flakes:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    p2p-anycast.url = "github:p2p-anycast/p2p-anycast";
  };

  outputs = { self, nixpkgs, p2p-anycast }: {
    nixosConfigurations.my-edge-vps = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        p2p-anycast.nixosModules.default
        {
          # Enable Edge Router
          services.anycast-edge = {
            enable = true;
            listenP2P = "/ip4/0.0.0.0/udp/9090/quic-v1";
            manifest = /etc/anycast/edge_manifest.pb;
            caPub = /etc/anycast/ca.pub;
            identityKey = "/var/lib/anycast-edge/identity.key";
            openFirewall = true;
          };
        }
      ];
    };

    nixosConfigurations.my-origin-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        p2p-anycast.nixosModules.default
        {
          # Enable Origin Sidecar
          services.anycast-origin = {
            enable = true;
            manifest = /etc/anycast/origin_manifest.pb;
            caPub = /etc/anycast/ca.pub;
            identityKey = "/var/lib/anycast-origin/identity.key";
            settings = {
              edge_multiaddrs = [
                "/ip4/203.0.113.10/udp/9090/quic-v1/p2p/12D3KooWEdgePeerID..."
              ];
              origin_master_key = "4f8a3c10b7e289d04f8a3c10b7e289d04f8a3c10b7e289d04f8a3c10b7e289d0";
              services = [
                {
                  service_id = "pbx-sip";
                  protocol = "UDP";
                  public_port = 5060;
                  policy = "STRICT_SINGLETON";
                  target = "127.0.0.1:5060";
                }
              ];
            };
          };
        }
      ];
    };
  };
}
```

### 3. Docker / OCI Containers (GHCR)

Pre-built minimal layered OCI container images are automatically built with Nix and published to GitHub Container Registry (`ghcr.io`). Since MeshCast uses an internal Post-Quantum ML-DSA-87 Root CA rather than Web PKI, the images contain zero unnecessary external CA bundles.

Root CA public keys can be passed as a file path, inline PEM string via `--ca-pub`, or through the `ANYCAST_CA_PUB` environment variable:

```bash
# Pull and run Edge Router container (using volume)
docker run -d \
  --name anycast-edge \
  --net=host \
  -v /etc/anycast:/data \
  ghcr.io/<owner>/anycast-edge:latest \
  --listen-p2p "/ip4/0.0.0.0/udp/9090/quic-v1" \
  --manifest /data/edge_manifest.pb \
  --ca-pub /data/ca.pub \
  --identity-key /data/identity.key

# Alternatively pass CA public key directly via environment variable or inline string:
docker run -d \
  --name anycast-edge \
  --net=host \
  -e ANYCAST_CA_PUB="-----BEGIN ML-DSA-87 PUBLIC KEY...-----" \
  -v /etc/anycast:/data \
  ghcr.io/<owner>/anycast-edge:latest \
  --listen-p2p "/ip4/0.0.0.0/udp/9090/quic-v1" \
  --manifest /data/edge_manifest.pb \
  --identity-key /data/identity.key

# Pull and run Origin Sidecar container
docker run -d \
  --name anycast-origin \
  --net=host \
  -v /etc/anycast:/data \
  ghcr.io/<owner>/anycast-origin:latest \
  --config /data/origin_config.json \
  --manifest /data/origin_manifest.pb \
  --ca-pub /data/ca.pub \
  --identity-key /data/identity.key
```

You can also build the OCI images locally using Nix without a running Docker daemon:

```bash
nix build .#edge-image -o result-edge-image
docker load < result-edge-image

nix build .#origin-image -o result-origin-image
docker load < result-origin-image
```

---


## Testing & Verification

Run the entire test suite with race detection enabled:

```bash
# Run unit and integration tests with race detector
go test -v -race ./...

# Or run specific test packages
go test -v -race ./pkg/pki/...
go test -v -race ./pkg/control/...
go test -v -race ./pkg/edge/...
go test -v -race ./pkg/origin/...
go test -v -race ./test/...
```

Run code formatting and vetting:

```bash
go vet ./...
```

---

## License

Apache 2.0. See LICENSE for details.
