package test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2p-anycast/pkg/control/gossip"
	"p2p-anycast/pkg/control/lease"
	control "p2p-anycast/pkg/proto/control"
	"p2p-anycast/pkg/edge/ingress"
	"p2p-anycast/pkg/origin/dialer"
	"p2p-anycast/pkg/origin/dispatch"
	"p2p-anycast/pkg/origin/nat"
	"p2p-anycast/pkg/pki/keystore"
	identity "p2p-anycast/pkg/proto/identity"
	"p2p-anycast/pkg/transport/auth"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

func TestE2EUDPSymmetricNATAndVoIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pki := SetupTestPKI(t)
	originMasterKey := []byte("master-secret-for-test-udp-nat32")

	// 1. Mock UDP PBX Echo Backend
	udpBackendConn, udpBackendAddr := StartMockUDPEchoServer(t)
	defer udpBackendConn.Close()

	// 2. Setup Edge Host
	edgeKey, _ := keystore.LoadOrGenerateIdentity(keystore.Options{ForceTier: keystore.TierRAM})
	edgeHost, err := p2pquic.NewHost(ctx, edgeKey, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create edge host: %v", err)
	}
	defer edgeHost.Close()

	edgeManifest := pki.IssueManifest(t, "edge-udp-01", identity.NodeRole_EDGE_ROUTER, edgeKey, nil)
	edgeAuth := auth.NewAuthenticator(edgeHost, edgeKey, edgeManifest, pki.CAPub)
	edgeAuth.RegisterStreamHandler()

	// Reserve a free UDP port for public listener
	freeUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to get free UDP port: %v", err)
	}
	publicPort := uint32(freeUDP.LocalAddr().(*net.UDPAddr).Port)
	freeUDP.Close()

	var edgeRouter *ingress.Router
	leaseMgr := lease.NewManager(lease.Config{
		OnRegister: func(reg *control.ServiceRegistration) {
			if edgeRouter != nil {
				edgeRouter.SyncPortListener(reg.PublicPort)
			}
		},
		OnEvict: func(reg *control.ServiceRegistration) {
			if edgeRouter != nil {
				edgeRouter.SyncPortListener(reg.PublicPort)
			}
		},
	})
	defer leaseMgr.Close()

	edgeRouter = ingress.NewRouter(ctx, edgeHost, leaseMgr, nil)
	defer edgeRouter.Close()

	_, err = gossip.NewMeshRegistry(ctx, edgeHost, func(reg *control.ServiceRegistration) {
		pID, _ := peer.Decode(reg.OriginPeerId)
		if _, ok := edgeAuth.GetSession(pID); ok {
			_ = leaseMgr.Register(reg)
		}
	})
	if err != nil {
		t.Fatalf("failed to create edge registry: %v", err)
	}

	// 3. Setup Origin Host
	originKey, _ := keystore.LoadOrGenerateIdentity(keystore.Options{ForceTier: keystore.TierRAM})
	originHost, err := p2pquic.NewHost(ctx, originKey, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create origin host: %v", err)
	}
	defer originHost.Close()

	originCaps := []*identity.ServiceCapability{
		{
			ServicePattern: "pbx-*",
			AllowedPolicies: []identity.AuthorizedPolicy{
				identity.AuthorizedPolicy_POLICY_CLUSTERED_RTT,
			},
			AllowedPorts: []*identity.PortRange{
				{Start: publicPort, End: publicPort},
			},
		},
	}
	originManifest := pki.IssueManifest(t, "origin-udp-01", identity.NodeRole_ORIGIN_NODE, originKey, originCaps)
	originAuth := auth.NewAuthenticator(originHost, originKey, originManifest, pki.CAPub)

	originRoutes := dispatch.NewTable()
	natTable := nat.NewTable(ctx, originHost, originMasterKey, originRoutes)
	defer natTable.Close()

	originRegistry, err := gossip.NewMeshRegistry(ctx, originHost, nil)
	if err != nil {
		t.Fatalf("failed to create origin registry: %v", err)
	}
	defer originRegistry.Close()

	edgeMultiaddrStr := fmt.Sprintf("%s/p2p/%s", edgeHost.Addrs()[0], edgeHost.ID())
	originNode, err := dialer.NewOriginNode(ctx, dialer.Config{
		Host:          originHost,
		Authenticator: originAuth,
		Registry:      originRegistry,
		Routes:        originRoutes,
		NATTable:      natTable,
		OriginKey:     originMasterKey,
		EdgeAddrs:     []string{edgeMultiaddrStr},
		Services: []dialer.ServiceConfig{
			{
				ServiceID:  "pbx-voip",
				Protocol:   control.TransportProtocol_UDP,
				PublicPort: publicPort,
				Policy:     control.RoutingPolicy_CLUSTERED_RTT,
				Target:     udpBackendAddr,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create origin node: %v", err)
	}
	defer originNode.Close()
	originNode.Start()

	// Wait for registration to propagate to edge
	deadline := time.Now().Add(6 * time.Second)
	registered := false
	for time.Now().Before(deadline) {
		if len(leaseMgr.GetRegistrationsForPort(publicPort)) > 0 {
			registered = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !registered {
		t.Fatalf("UDP service failed to register on edge within timeout")
	}

	edgeTarget := fmt.Sprintf("127.0.0.1:%d", publicPort)
	edgeUDPAddr, err := net.ResolveUDPAddr("udp", edgeTarget)
	if err != nil {
		t.Fatalf("failed to resolve edge UDP addr: %v", err)
	}

	// 4. Client 1: Send SIP datagram
	client1Conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to create client1 UDP: %v", err)
	}
	defer client1Conn.Close()

	client1Msg := []byte("INVITE sip:alice@meshcast SIP/2.0")
	if _, err := client1Conn.WriteToUDP(client1Msg, edgeUDPAddr); err != nil {
		t.Fatalf("client1 write failed: %v", err)
	}

	buf1 := make([]byte, 2048)
	_ = client1Conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n1, _, err := client1Conn.ReadFromUDP(buf1)
	if err != nil {
		t.Fatalf("client1 failed to receive echo: %v", err)
	}
	if string(buf1[:n1]) != string(client1Msg) {
		t.Fatalf("client1 echo mismatch: got %s", buf1[:n1])
	}

	// 5. Client 2: Send RTP media datagram
	client2Conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to create client2 UDP: %v", err)
	}
	defer client2Conn.Close()

	client2Msg := []byte("RTP-MEDIA-PACKET-PAYLOAD-007")
	if _, err := client2Conn.WriteToUDP(client2Msg, edgeUDPAddr); err != nil {
		t.Fatalf("client2 write failed: %v", err)
	}

	buf2 := make([]byte, 2048)
	_ = client2Conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n2, _, err := client2Conn.ReadFromUDP(buf2)
	if err != nil {
		t.Fatalf("client2 failed to receive echo: %v", err)
	}
	if string(buf2[:n2]) != string(client2Msg) {
		t.Fatalf("client2 echo mismatch: got %s", buf2[:n2])
	}

	// Verify both client flows exist in NAT table
	if natTable.ActiveSessionCount() < 2 {
		t.Fatalf("expected at least 2 active NAT sessions on origin, got %d", natTable.ActiveSessionCount())
	}
}
