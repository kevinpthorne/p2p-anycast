package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"p2p-anycast/pkg/control/gossip"
	control "p2p-anycast/pkg/proto/control"
	"p2p-anycast/pkg/origin/dialer"
	"p2p-anycast/pkg/origin/dispatch"
	"p2p-anycast/pkg/origin/k8s"
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
	Services        []ServiceConfigJSON  `json:"services"`
}

type ServiceConfigJSON struct {
	ServiceID           string `json:"service_id"`
	Protocol            string `json:"protocol"` // "TCP", "UDP", "TCP_AND_UDP"
	PublicPort          uint32 `json:"public_port"`
	Policy              string `json:"policy"` // "CLUSTERED_RTT", "FAILOVER_STANDBY", "STRICT_SINGLETON"
	SNIHostname         string `json:"sni_hostname"`
	Target              string `json:"target"` // "127.0.0.1:5060", "cluster.svc:25565", or "unix:///path"
	EnableProxyProtocol bool   `json:"enable_proxy_protocol"`
}

func main() {
	configPath := flag.String("config", "origin_config.json", "Path to Origin configuration JSON")
	manifestPath := flag.String("manifest", "origin_manifest.pb", "Path to Origin SignedCapabilityManifest")
	caPubPath := flag.String("ca-pub", "ca.pub", "Path to trusted Root CA public key (PEM)")
	identityKeyPath := flag.String("identity-key", "identity.key", "Path to hardware/filesystem identity key")
	printPeerID := flag.Bool("print-peer-id", false, "Print the libp2p Peer ID derived from the identity key and exit")
	masterKeyFile := flag.String("master-key-file", "", "Path to file containing Origin 256-bit master key in hex")
	k8sEnable := flag.Bool("k8s", false, "Enable Kubernetes service discovery via annotations")
	k8sDefaultGatewayTarget := flag.String("k8s-default-gateway-target", "", "Default fallback gateway target for TLS SNI services (e.g. cilium-gateway.kube-system.svc.cluster.local:443)")
	k8sAPIServer := flag.String("k8s-api-server", "", "Kubernetes API server base URL")
	k8sToken := flag.String("k8s-token", "", "Kubernetes Bearer token or path to token file")
	k8sCACert := flag.String("k8s-ca-cert", "", "Path to Kubernetes CA certificate")
	k8sNamespace := flag.String("k8s-namespace", "", "Kubernetes namespace to discover services from (default: all namespaces)")
	k8sAnnotationPrefix := flag.String("k8s-annotation-prefix", "", "Custom annotation prefix (default: p2p-anycast.io and anycast.io)")
	k8sInsecure := flag.Bool("k8s-insecure-skip-tls-verify", false, "Skip TLS verification when connecting to Kubernetes API")
	flag.Parse()

	// 1. Load Origin Identity Key (TPM2 -> Secure Enclave -> Filesystem)
	idKey, err := keystore.LoadOrGenerateIdentity(keystore.Options{
		KeyFilePath: *identityKeyPath,
		AllowCreate: true,
	})
	if err != nil {
		log.Fatalf("[Origin] Failed to load node identity: %v", err)
	}

	if *printPeerID {
		fmt.Println(idKey.PeerID().String())
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Printf("[Origin] Starting MeshCast Origin Sidecar...")
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

	var envKey string
	if *masterKeyFile != "" {
		keyBytes, err := os.ReadFile(*masterKeyFile)
		if err != nil {
			if credDir := os.Getenv("CREDENTIALS_DIRECTORY"); credDir != "" {
				candidates := []string{
					filepath.Join(credDir, filepath.Base(*masterKeyFile)),
					filepath.Join(credDir, "master.key"),
				}
				for _, c := range candidates {
					if cData, cErr := os.ReadFile(c); cErr == nil {
						keyBytes = cData
						err = nil
						break
					}
				}
			}
		}
		if err != nil {
			log.Fatalf("[Origin] Failed to read master key file %s: %v", *masterKeyFile, err)
		}
		envKey = strings.TrimSpace(string(keyBytes))
	} else if keyEnv := os.Getenv("ORIGIN_MASTER_KEY"); keyEnv != "" {
		envKey = keyEnv
	} else {
		log.Fatalf("[Origin] A master key must be provided via --master-key-file or ORIGIN_MASTER_KEY environment variable")
	}

	var originMasterKey []byte
	if decoded, err := hex.DecodeString(envKey); err == nil && len(decoded) > 0 {
		originMasterKey = decoded
	} else {
		originMasterKey = []byte(envKey)
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

	if *k8sEnable || os.Getenv("ANYCAST_K8S") == "true" {
		k8sClient, err := k8s.NewClient(k8s.ClientConfig{
			APIServerURL:          *k8sAPIServer,
			Token:                 *k8sToken,
			CACertFile:            *k8sCACert,
			Namespace:              *k8sNamespace,
			InsecureSkipTLSVerify: *k8sInsecure,
		})
		if err != nil {
			log.Fatalf("[Origin] Failed to initialize Kubernetes client: %v", err)
		}

		k8sServices, err := k8sClient.ListServices(ctx, *k8sNamespace)
		if err != nil {
			log.Fatalf("[Origin] Failed to list Kubernetes services: %v", err)
		}

		k8sTLSRoutes, err := k8sClient.ListTLSRoutes(ctx, *k8sNamespace)
		if err != nil {
			log.Printf("[Origin] Warning: failed to list TLSRoutes: %v", err)
		}

		discovered := k8s.BuildServicesFromK8s(k8sServices, k8sTLSRoutes, k8s.BuilderOptions{
			AnnotationPrefix:     *k8sAnnotationPrefix,
			DefaultGatewayTarget: *k8sDefaultGatewayTarget,
		})

		log.Printf("[Origin] Discovered %d service(s) from Kubernetes annotations", len(discovered))
		for _, d := range discovered {
			log.Printf("[Origin]   -> [%s] %s:%d (policy: %s, sni: %q, target: %s)",
				d.ServiceID, d.Protocol, d.PublicPort, d.Policy, d.SNIHostname, d.Target)
		}

		services = append(services, discovered...)
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
