package dialer

import (
	"context"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2p-anycast/pkg/control/discovery"
	"p2p-anycast/pkg/control/gossip"
	"p2p-anycast/pkg/control/lease"
	"p2p-anycast/pkg/origin/dispatch"
	"p2p-anycast/pkg/pki/keystore"
	"p2p-anycast/pkg/pki/manifest"
	"p2p-anycast/pkg/pki/mldsa"
	control "p2p-anycast/pkg/proto/control"
	identity "p2p-anycast/pkg/proto/identity"
	"p2p-anycast/pkg/transport/auth"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

type testPKI struct {
	caPub  *mldsa87.PublicKey
	caPriv *mldsa87.PrivateKey
}

func setupTestPKI(t *testing.T) *testPKI {
	pub, priv, err := mldsa.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate Root CA key: %v", err)
	}
	return &testPKI{caPub: pub, caPriv: priv}
}

func (p *testPKI) issueManifest(t *testing.T, subjectID string, role identity.NodeRole, idKey *keystore.IdentityKey, caps []*identity.ServiceCapability) *identity.SignedCapabilityManifest {
	now := time.Now()
	claims := &identity.IdentityClaims{
		SerialNumber: 1,
		IssuerId:     "Test Root CA",
		SubjectId:    subjectID,
		Role:         role,
		Libp2PPeerId: idKey.PeerID().String(),
		NotBefore:    now.Add(-1 * time.Hour).Unix(),
		NotAfter:     now.Add(24 * time.Hour).Unix(),
		Capabilities: caps,
	}

	signed, err := manifest.SignManifest(claims, p.caPriv, p.caPub)
	if err != nil {
		t.Fatalf("failed to sign test manifest: %v", err)
	}
	return signed
}

func TestE2EDynamicDiscoveryAndRegistration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	pki := setupTestPKI(t)
	originMasterKey := []byte("master-secret-for-discovery-test")

	// 1. Setup Edge 1 (DHT Server, seed node)
	edge1Key, err := keystore.GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate edge1 key: %v", err)
	}
	edge1Host, err := p2pquic.NewHost(ctx, edge1Key, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create edge1 host: %v", err)
	}
	defer edge1Host.Close()

	edge1Manifest := pki.issueManifest(t, "edge-01", identity.NodeRole_EDGE_ROUTER, edge1Key, nil)
	edge1Auth := auth.NewAuthenticator(edge1Host, edge1Key, edge1Manifest, pki.caPub)
	edge1Auth.RegisterStreamHandler()

	leaseMgr1 := lease.NewManager(lease.Config{})
	defer leaseMgr1.Close()

	edge1Registry, err := gossip.NewMeshRegistry(ctx, edge1Host, func(reg *control.ServiceRegistration) {
		pID, _ := peer.Decode(reg.OriginPeerId)
		if _, ok := edge1Auth.GetSession(pID); ok {
			_ = leaseMgr1.Register(reg)
		}
	})
	if err != nil {
		t.Fatalf("failed to create edge1 registry: %v", err)
	}
	defer edge1Registry.Close()

	edge1Adv, err := discovery.NewEdgeAdvertiser(ctx, edge1Host, nil, discovery.WithAdvertiseInterval(200*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create edge1 advertiser: %v", err)
	}
	defer edge1Adv.Close()

	edge1Addrs, err := peer.AddrInfoToP2pAddrs(&peer.AddrInfo{ID: edge1Host.ID(), Addrs: edge1Host.Addrs()})
	if err != nil {
		t.Fatalf("failed to get edge1 p2p addrs: %v", err)
	}

	// 2. Setup Edge 2 (DHT Server, bootstrapped to Edge 1)
	edge2Key, err := keystore.GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate edge2 key: %v", err)
	}
	edge2Host, err := p2pquic.NewHost(ctx, edge2Key, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create edge2 host: %v", err)
	}
	defer edge2Host.Close()

	edge2Manifest := pki.issueManifest(t, "edge-02", identity.NodeRole_EDGE_ROUTER, edge2Key, nil)
	edge2Auth := auth.NewAuthenticator(edge2Host, edge2Key, edge2Manifest, pki.caPub)
	edge2Auth.RegisterStreamHandler()

	leaseMgr2 := lease.NewManager(lease.Config{})
	defer leaseMgr2.Close()

	edge2Registry, err := gossip.NewMeshRegistry(ctx, edge2Host, func(reg *control.ServiceRegistration) {
		pID, _ := peer.Decode(reg.OriginPeerId)
		if _, ok := edge2Auth.GetSession(pID); ok {
			_ = leaseMgr2.Register(reg)
		}
	})
	if err != nil {
		t.Fatalf("failed to create edge2 registry: %v", err)
	}
	defer edge2Registry.Close()

	edge2Adv, err := discovery.NewEdgeAdvertiser(ctx, edge2Host, edge1Addrs, discovery.WithAdvertiseInterval(200*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create edge2 advertiser: %v", err)
	}
	defer edge2Adv.Close()

	// Connect Edge 2 directly to Edge 1 to form DHT mesh immediately
	if err := edge2Host.Connect(ctx, peer.AddrInfo{ID: edge1Host.ID(), Addrs: edge1Host.Addrs()}); err != nil {
		t.Fatalf("failed to connect edge2 to edge1: %v", err)
	}

	// 3. Setup Origin with bootstrap list containing ONLY Edge 1
	originKey, err := keystore.GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate origin key: %v", err)
	}
	originHost, err := p2pquic.NewHost(ctx, originKey, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create origin host: %v", err)
	}
	defer originHost.Close()

	originCaps := []*identity.ServiceCapability{
		{
			ServicePattern: "*",
			AllowedPolicies: []identity.AuthorizedPolicy{
				identity.AuthorizedPolicy_POLICY_CLUSTERED_RTT,
			},
			AllowedPorts: []*identity.PortRange{
				{Start: 1, End: 65535},
			},
		},
	}
	originManifest := pki.issueManifest(t, "origin-01", identity.NodeRole_ORIGIN_NODE, originKey, originCaps)
	originAuth := auth.NewAuthenticator(originHost, originKey, originManifest, pki.caPub)
	originAuth.RegisterStreamHandler()

	originRegistry, err := gossip.NewMeshRegistry(ctx, originHost, nil)
	if err != nil {
		t.Fatalf("failed to create origin registry: %v", err)
	}
	defer originRegistry.Close()

	routes := dispatch.NewTable()
	services := []ServiceConfig{
		{
			ServiceID:  "pbx-core",
			Protocol:   control.TransportProtocol_UDP,
			PublicPort: 5060,
			Policy:     control.RoutingPolicy_CLUSTERED_RTT,
			Target:     "127.0.0.1:5060",
		},
	}

	originNode, err := NewOriginNode(ctx, Config{
		Host:              originHost,
		Authenticator:     originAuth,
		Registry:          originRegistry,
		Routes:            routes,
		OriginKey:         originMasterKey,
		EdgeAddrs:         []string{edge1Addrs[0].String()}, // ONLY Edge 1!
		Services:          services,
		EnableDHT:         true,
		DiscoveryInterval: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create OriginNode: %v", err)
	}
	defer originNode.Close()

	originNode.Start()

	// 4. Assert Origin registers on Edge 1 (static)
	deadline := time.Now().Add(10 * time.Second)
	registeredEdge1 := false
	for time.Now().Before(deadline) {
		regs := leaseMgr1.GetRegistrationsForPort(5060)
		for _, r := range regs {
			if r.ServiceId == "pbx-core" {
				registeredEdge1 = true
				break
			}
		}
		if registeredEdge1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !registeredEdge1 {
		t.Fatalf("Origin failed to register service on static Edge 1")
	}

	// 5. Assert Origin dynamically discovers Edge 2 via DHT, connects, authenticates, and registers service
	registeredEdge2 := false
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		regs := leaseMgr2.GetRegistrationsForPort(5060)
		for _, r := range regs {
			if r.ServiceId == "pbx-core" {
				registeredEdge2 = true
				break
			}
		}
		if registeredEdge2 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if !registeredEdge2 {
		t.Fatalf("Origin failed to dynamically discover and register service on Edge 2")
	}

	// Verify Edge 2 is in Origin's active edges
	active := originNode.ActiveEdges()
	foundEdge2 := false
	for _, id := range active {
		if id == edge2Host.ID() {
			foundEdge2 = true
			break
		}
	}
	if !foundEdge2 {
		t.Fatalf("Edge 2 ID %s not found in Origin's active edges: %v", edge2Host.ID(), active)
	}
}

func TestSecurityInvariantUntrustedDHTPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pki := setupTestPKI(t)
	originMasterKey := []byte("master-secret-security-test-key")

	// 1. Setup legitimate Edge 1 (seed node)
	edge1Key, err := keystore.GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate edge1 key: %v", err)
	}
	edge1Host, err := p2pquic.NewHost(ctx, edge1Key, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create edge1 host: %v", err)
	}
	defer edge1Host.Close()

	edge1Manifest := pki.issueManifest(t, "edge-01", identity.NodeRole_EDGE_ROUTER, edge1Key, nil)
	edge1Auth := auth.NewAuthenticator(edge1Host, edge1Key, edge1Manifest, pki.caPub)
	edge1Auth.RegisterStreamHandler()

	edge1Adv, err := discovery.NewEdgeAdvertiser(ctx, edge1Host, nil, discovery.WithAdvertiseInterval(200*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create edge1 advertiser: %v", err)
	}
	defer edge1Adv.Close()

	edge1Addrs, err := peer.AddrInfoToP2pAddrs(&peer.AddrInfo{ID: edge1Host.ID(), Addrs: edge1Host.Addrs()})
	if err != nil {
		t.Fatalf("failed to get edge1 p2p addrs: %v", err)
	}

	// 2. Setup Rogue Peer: Advertises on DHT topic but has NO valid Root CA manifest
	rogueKey, err := keystore.GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate rogue key: %v", err)
	}
	rogueHost, err := p2pquic.NewHost(ctx, rogueKey, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create rogue host: %v", err)
	}
	defer rogueHost.Close()

	// Rogue node creates advertiser bootstrapped to Edge 1
	rogueAdv, err := discovery.NewEdgeAdvertiser(ctx, rogueHost, edge1Addrs, discovery.WithAdvertiseInterval(200*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create rogue advertiser: %v", err)
	}
	defer rogueAdv.Close()

	if err := rogueHost.Connect(ctx, peer.AddrInfo{ID: edge1Host.ID(), Addrs: edge1Host.Addrs()}); err != nil {
		t.Fatalf("failed to connect rogue to edge1: %v", err)
	}

	// 3. Setup Origin
	originKey, err := keystore.GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate origin key: %v", err)
	}
	originHost, err := p2pquic.NewHost(ctx, originKey, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create origin host: %v", err)
	}
	defer originHost.Close()

	originCaps := []*identity.ServiceCapability{
		{
			ServicePattern: "*",
			AllowedPolicies: []identity.AuthorizedPolicy{
				identity.AuthorizedPolicy_POLICY_CLUSTERED_RTT,
			},
			AllowedPorts: []*identity.PortRange{
				{Start: 1, End: 65535},
			},
		},
	}
	originManifest := pki.issueManifest(t, "origin-01", identity.NodeRole_ORIGIN_NODE, originKey, originCaps)
	originAuth := auth.NewAuthenticator(originHost, originKey, originManifest, pki.caPub)
	originAuth.RegisterStreamHandler()

	originRegistry, err := gossip.NewMeshRegistry(ctx, originHost, nil)
	if err != nil {
		t.Fatalf("failed to create origin registry: %v", err)
	}
	defer originRegistry.Close()

	routes := dispatch.NewTable()
	services := []ServiceConfig{
		{
			ServiceID:  "secure-service",
			Protocol:   control.TransportProtocol_TCP,
			PublicPort: 8080,
			Policy:     control.RoutingPolicy_CLUSTERED_RTT,
			Target:     "127.0.0.1:8080",
		},
	}

	originNode, err := NewOriginNode(ctx, Config{
		Host:              originHost,
		Authenticator:     originAuth,
		Registry:          originRegistry,
		Routes:            routes,
		OriginKey:         originMasterKey,
		EdgeAddrs:         []string{edge1Addrs[0].String()},
		Services:          services,
		EnableDHT:         true,
		DiscoveryInterval: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create origin node: %v", err)
	}
	defer originNode.Close()

	originNode.Start()

	// Wait for discovery cycles to run
	time.Sleep(2 * time.Second)

	// Assert: Rogue host MUST NOT be in ActiveEdges
	active := originNode.ActiveEdges()
	for _, id := range active {
		if id == rogueHost.ID() {
			t.Fatalf("SECURITY VIOLATION: Rogue host %s was accepted into active edges!", rogueHost.ID())
		}
	}

	// Assert: No active connections to rogue host
	connsToRogue := originHost.Network().ConnsToPeer(rogueHost.ID())
	for _, c := range connsToRogue {
		t.Logf("Rogue conn: local=%v remote=%v direction=%v closed=%v", c.LocalMultiaddr(), c.RemoteMultiaddr(), c.Stat().Direction, c.IsClosed())
		for _, s := range c.GetStreams() {
			t.Logf("  stream: proto=%v stat=%+v", s.Protocol(), s.Stat())
		}
	}
	if len(connsToRogue) > 0 {
		t.Fatalf("SECURITY VIOLATION: Connection to untrusted rogue host %s was not dropped!", rogueHost.ID())
	}
}
