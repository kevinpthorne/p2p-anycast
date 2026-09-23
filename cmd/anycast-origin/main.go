package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"p2p-anycast/pkg/control/gossip"
	control "p2p-anycast/pkg/proto/control"
	"p2p-anycast/pkg/origin/dialer"
	"p2p-anycast/pkg/origin/dispatch"
	"p2p-anycast/pkg/origin/nat"
	"p2p-anycast/pkg/origin/stream"
	"p2p-anycast/pkg/pki/keystore"
	"p2p-anycast/pkg/pki/manifest"
	"p2p-anycast/pkg/pki/mldsa"
	"p2p-anycast/pkg/transport/auth"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

type OriginConfigJSON struct {
	EdgeMultiaddrs  []string             `json:"edge_multiaddrs"`
	OriginMasterKey string               `json:"origin_master_key"`
	Services        []ServiceConfigJSON  `json:"services"`
}

type ServiceConfigJSON struct {
	ServiceID           string `json:"service_id"`
	Protocol            string `json:"protocol"` // "TCP", "UDP", "TCP_AND_UDP"
	PublicPort          uint32 `json:"public_port"`
	Policy              string `json:"policy"` // "CLUSTERED_RTT", "TLS_SNI", "FAILOVER_STANDBY", "STRICT_SINGLETON"
	SNIHostname         string `json:"sni_hostname"`
	Target              string `json:"target"` // "127.0.0.1:5060", "cluster.svc:25565", or "unix:///path"
	EnableProxyProtocol bool   `json:"enable_proxy_protocol"`
}

func main() {
	configPath := flag.String("config", "origin_config.json", "Path to Origin configuration JSON")
	manifestPath := flag.String("manifest", "origin_manifest.pb", "Path to Origin SignedCapabilityManifest")
	caPubPath := flag.String("ca-pub", "ca.pub", "Path to trusted Root CA public key (PEM)")
	identityKeyPath := flag.String("identity-key", "identity.key", "Path to hardware/filesystem identity key")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Printf("[Origin] Starting MeshCast Origin Sidecar...")

	// 1. Load Origin Identity Key
	idKey, err := keystore.LoadOrGenerateIdentity(keystore.Options{
		KeyFilePath: *identityKeyPath,
		AllowCreate: true,
	})
	if err != nil {
		log.Fatalf("[Origin] Failed to load node identity: %v", err)
	}
	log.Printf("[Origin] Loaded identity from %s (Peer ID: %s)", idKey.Tier(), idKey.PeerID())

	// 2. Load Root CA Public Key (from file, inline PEM string, or ANYCAST_CA_PUB env)
	caPub, err := mldsa.LoadPublicKey(*caPubPath)
	if err != nil {
		log.Fatalf("[Origin] Failed to load Root CA public key: %v", err)
	}

	// 3. Load Origin Capability Manifest (accepts binary .pb or base64 text)
	signedManifest, err := manifest.LoadManifestFile(*manifestPath)
	if err != nil {
		log.Fatalf("[Origin] Failed to load manifest %s: %v", *manifestPath, err)
	}
	originClaims, err := manifest.VerifyManifest(signedManifest, caPub)
	if err != nil {
		log.Fatalf("[Origin] Origin manifest verification failed: %v", err)
	}
	log.Printf("[Origin] Verified capability manifest for subject %q", originClaims.SubjectId)

	// 4. Load Origin Config JSON
	configBytes, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("[Origin] Failed to read config file %s: %v", *configPath, err)
	}
	var cfgJSON OriginConfigJSON
	if err := json.Unmarshal(configBytes, &cfgJSON); err != nil {
		log.Fatalf("[Origin] Failed to parse config JSON: %v", err)
	}

	var originMasterKey []byte
	if decoded, err := hex.DecodeString(cfgJSON.OriginMasterKey); err == nil && len(decoded) > 0 {
		originMasterKey = decoded
	} else {
		originMasterKey = []byte(cfgJSON.OriginMasterKey)
	}
	if len(originMasterKey) == 0 {
		originMasterKey = []byte("default-meshcast-origin-master-key")
	}

	// Parse services
	var services []dialer.ServiceConfig
	for _, s := range cfgJSON.Services {
		var protoType control.TransportProtocol
		switch strings.ToUpper(s.Protocol) {
		case "TCP":
			protoType = control.TransportProtocol_TCP
		case "UDP":
			protoType = control.TransportProtocol_UDP
		case "TCP_AND_UDP":
			protoType = control.TransportProtocol_TCP_AND_UDP
		default:
			protoType = control.TransportProtocol_TCP
		}

		var policy control.RoutingPolicy
		switch strings.ToUpper(s.Policy) {
		case "CLUSTERED_RTT":
			policy = control.RoutingPolicy_CLUSTERED_RTT
		case "TLS_SNI":
			policy = control.RoutingPolicy_TLS_SNI
		case "FAILOVER_STANDBY":
			policy = control.RoutingPolicy_FAILOVER_STANDBY
		case "STRICT_SINGLETON":
			policy = control.RoutingPolicy_STRICT_SINGLETON
		default:
			policy = control.RoutingPolicy_CLUSTERED_RTT
		}

		services = append(services, dialer.ServiceConfig{
			ServiceID:           s.ServiceID,
			Protocol:            protoType,
			PublicPort:          s.PublicPort,
			Policy:              policy,
			SNIHostname:         s.SNIHostname,
			Target:              s.Target,
			EnableProxyProtocol: s.EnableProxyProtocol,
		})
	}

	// 5. Start libp2p Host (outbound on ephemeral UDP port)
	h, err := p2pquic.NewHost(ctx, idKey, []string{"/ip4/0.0.0.0/udp/0/quic-v1"})
	if err != nil {
		log.Fatalf("[Origin] Failed to create libp2p host: %v", err)
	}
	defer h.Close()

	// 6. Setup Auth, Routes, Stream Handler, NAT Table, GossipSub
	authenticator := auth.NewAuthenticator(h, idKey, signedManifest, caPub)
	routes := dispatch.NewTable()
	_ = stream.NewHandler(h, originMasterKey, routes)
	natTable := nat.NewTable(ctx, h, originMasterKey, routes)
	defer natTable.Close()

	registry, err := gossip.NewMeshRegistry(ctx, h, nil)
	if err != nil {
		log.Fatalf("[Origin] Failed to initialize MeshRegistry: %v", err)
	}
	defer registry.Close()

	// 7. Initialize Origin Dialer Node
	originNode, err := dialer.NewOriginNode(ctx, dialer.Config{
		Host:          h,
		Authenticator: authenticator,
		Registry:      registry,
		Routes:        routes,
		NATTable:      natTable,
		OriginKey:     originMasterKey,
		EdgeAddrs:     cfgJSON.EdgeMultiaddrs,
		Services:      services,
	})
	if err != nil {
		log.Fatalf("[Origin] Failed to create OriginNode: %v", err)
	}
	defer originNode.Close()

	originNode.Start()
	log.Printf("[Origin] Outbound dialer started, connected to %d edges.", len(cfgJSON.EdgeMultiaddrs))

	// Wait for OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Printf("[Origin] Shutting down...")
}
