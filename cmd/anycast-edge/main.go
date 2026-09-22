package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	"p2p-anycast/pkg/control/gossip"
	"p2p-anycast/pkg/control/lease"
	"p2p-anycast/pkg/edge/ingress"
	"p2p-anycast/pkg/pki/keystore"
	"p2p-anycast/pkg/pki/manifest"
	"p2p-anycast/pkg/pki/mldsa"
	control "p2p-anycast/pkg/proto/control"
	identity "p2p-anycast/pkg/proto/identity"
	"p2p-anycast/pkg/transport/auth"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

func main() {
	p2pListen := flag.String("listen-p2p", "/ip4/0.0.0.0/udp/4002/quic-v1", "Multiaddr to listen for incoming QUIC connections from Origins")
	manifestPath := flag.String("manifest", "edge_manifest.pb", "Path to Edge SignedCapabilityManifest (manifest.pb)")
	caPubPath := flag.String("ca-pub", "ca.pub", "Path to trusted Root CA public key (PEM)")
	identityKeyPath := flag.String("identity-key", "identity.key", "Path to hardware/filesystem identity key")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Printf("[Edge] Starting MeshCast Edge Router...")

	// 1. Load Keystore Identity (TPM2 -> Secure Enclave -> Filesystem -> RAM)
	idKey, err := keystore.LoadOrGenerateIdentity(keystore.Options{
		KeyFilePath: *identityKeyPath,
		AllowCreate: true,
	})
	if err != nil {
		log.Fatalf("[Edge] Failed to load node identity: %v", err)
	}
	log.Printf("[Edge] Loaded identity from %s (Peer ID: %s)", idKey.Tier(), idKey.PeerID())

	// 2. Load Trusted Root CA Public Key (from file, inline PEM string, or ANYCAST_CA_PUB env)
	caPub, err := mldsa.LoadPublicKey(*caPubPath)
	if err != nil {
		log.Fatalf("[Edge] Failed to load Root CA public key: %v", err)
	}

	// 3. Load Edge Capability Manifest
	manifestBytes, err := os.ReadFile(*manifestPath)
	if err != nil {
		log.Fatalf("[Edge] Failed to read manifest %s: %v", *manifestPath, err)
	}
	var signedManifest identity.SignedCapabilityManifest
	if err := proto.Unmarshal(manifestBytes, &signedManifest); err != nil {
		log.Fatalf("[Edge] Failed to unmarshal manifest: %v", err)
	}
	edgeClaims, err := manifest.VerifyManifest(&signedManifest, caPub)
	if err != nil {
		log.Fatalf("[Edge] Edge manifest verification failed: %v", err)
	}
	log.Printf("[Edge] Verified capability manifest for subject %q", edgeClaims.SubjectId)

	// 4. Start libp2p Host with native QUIC transport and datagrams
	h, err := p2pquic.NewHost(ctx, idKey, []string{*p2pListen})
	if err != nil {
		log.Fatalf("[Edge] Failed to create libp2p host: %v", err)
	}
	defer h.Close()

	for _, addr := range h.Addrs() {
		log.Printf("[Edge] Listening on: %s/p2p/%s", addr, h.ID())
	}

	// 5. Setup Authentication Protocol (/p2p-anycast/auth/1.0.0)
	authenticator := auth.NewAuthenticator(h, idKey, &signedManifest, caPub)
	authenticator.RegisterStreamHandler()

	// 6. Setup Ingress Router & Lease Manager
	var router *ingress.Router
	leaseMgr := lease.NewManager(lease.Config{
		OnRegister: func(reg *control.ServiceRegistration) {
			log.Printf("[Edge] Service registered: %s (Port: %d, Policy: %v, Origin: %s)",
				reg.ServiceId, reg.PublicPort, reg.Policy, reg.OriginPeerId)
			if router != nil {
				router.SyncPortListener(reg.PublicPort)
			}
		},
		OnEvict: func(reg *control.ServiceRegistration) {
			log.Printf("[Edge] Service evicted: %s (Port: %d, Origin: %s)",
				reg.ServiceId, reg.PublicPort, reg.OriginPeerId)
			if router != nil {
				router.SyncPortListener(reg.PublicPort)
			}
		},
	})
	defer leaseMgr.Close()

	router = ingress.NewRouter(ctx, h, leaseMgr)
	defer router.Close()

	// 7. Setup GossipSub Control Plane (/p2p-anycast/registry/1.0.0)
	_, err = gossip.NewMeshRegistry(ctx, h, func(reg *control.ServiceRegistration) {
		// Verify origin has an active authenticated session
		pID, err := peer.Decode(reg.OriginPeerId)
		if err != nil {
			return
		}

		claims, ok := authenticator.GetSession(pID)
		if !ok {
			log.Printf("[Edge] Ignoring announcement from unauthenticated peer %s", pID)
			return
		}

		// Verify capability authorization
		var authPolicy identity.AuthorizedPolicy
		switch reg.Policy {
		case control.RoutingPolicy_CLUSTERED_RTT:
			authPolicy = identity.AuthorizedPolicy_POLICY_CLUSTERED_RTT
		case control.RoutingPolicy_TLS_SNI:
			authPolicy = identity.AuthorizedPolicy_POLICY_TLS_SNI
		case control.RoutingPolicy_FAILOVER_STANDBY:
			authPolicy = identity.AuthorizedPolicy_POLICY_FAILOVER_STANDBY
		case control.RoutingPolicy_STRICT_SINGLETON:
			authPolicy = identity.AuthorizedPolicy_POLICY_STRICT_SINGLETON
		}

		if err := manifest.CanAuthorizeService(claims, reg.ServiceId, reg.PublicPort, authPolicy); err != nil {
			log.Printf("[Edge] Unauthorized service advertisement %q on port %d from peer %s: %v",
				reg.ServiceId, reg.PublicPort, pID, err)
			return
		}

		// Handle message type
		switch reg.Type {
		case control.MessageType_ANNOUNCE:
			if err := leaseMgr.Register(reg); err != nil {
				log.Printf("[Edge] Failed to register service %s: %v", reg.ServiceId, err)
			}
		case control.MessageType_HEARTBEAT:
			var bID [16]byte
			copy(bID[:], reg.BindingId)
			_ = leaseMgr.Heartbeat(reg.OriginPeerId, bID, reg.LeaseEpoch)
		case control.MessageType_REVOKE:
			var bID [16]byte
			copy(bID[:], reg.BindingId)
			_ = leaseMgr.Revoke(reg.OriginPeerId, bID)
		}
	})
	if err != nil {
		log.Fatalf("[Edge] Failed to initialize MeshRegistry: %v", err)
	}

	log.Printf("[Edge] Ready to receive Origin connections and serve public traffic.")

	// Wait for OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Printf("[Edge] Shutting down...")
}
