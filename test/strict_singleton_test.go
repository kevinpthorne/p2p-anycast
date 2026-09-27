package test

import (
	"context"
	"fmt"
	"io"
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
	"p2p-anycast/pkg/origin/stream"
	"p2p-anycast/pkg/pki/keystore"
	identity "p2p-anycast/pkg/proto/identity"
	"p2p-anycast/pkg/transport/auth"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

func TestStrictSingletonFailClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pki := SetupTestPKI(t)
	originMasterKey := []byte("master-secret-singleton-test32")

	// 1. Mock TCP Backend
	backendLn, backendAddr := StartMockTCPEchoServer(t)
	defer backendLn.Close()

	// 2. Setup Edge Host
	edgeKey, _ := keystore.GenerateTestIdentity()
	edgeHost, err := p2pquic.NewHost(ctx, edgeKey, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create edge host: %v", err)
	}
	defer edgeHost.Close()

	edgeManifest := pki.IssueManifest(t, "edge-singleton-01", identity.NodeRole_EDGE_ROUTER, edgeKey, nil)
	edgeAuth := auth.NewAuthenticator(edgeHost, edgeKey, edgeManifest, pki.CAPub)
	edgeAuth.RegisterStreamHandler()

	// Reserve a free TCP port for public listener
	freeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free TCP port: %v", err)
	}
	publicPort := uint32(freeLn.Addr().(*net.TCPAddr).Port)
	freeLn.Close()

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

	// 3. Setup Origin 1 (Active Singleton)
	origin1Key, _ := keystore.GenerateTestIdentity()
	origin1Host, err := p2pquic.NewHost(ctx, origin1Key, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create origin1 host: %v", err)
	}

	origin1Caps := []*identity.ServiceCapability{
		{
			ServicePattern: "pbx-*",
			AllowedPolicies: []identity.AuthorizedPolicy{
				identity.AuthorizedPolicy_POLICY_STRICT_SINGLETON,
			},
			AllowedPorts: []*identity.PortRange{
				{Start: publicPort, End: publicPort},
			},
		},
	}
	origin1Manifest := pki.IssueManifest(t, "origin-singleton-01", identity.NodeRole_ORIGIN_NODE, origin1Key, origin1Caps)
	origin1Auth := auth.NewAuthenticator(origin1Host, origin1Key, origin1Manifest, pki.CAPub)

	origin1Routes := dispatch.NewTable()
	_ = stream.NewHandler(origin1Host, originMasterKey, origin1Routes)

	origin1Registry, err := gossip.NewMeshRegistry(ctx, origin1Host, nil)
	if err != nil {
		t.Fatalf("failed to create origin1 registry: %v", err)
	}
	defer origin1Registry.Close()

	edgeMultiaddrStr := fmt.Sprintf("%s/p2p/%s", edgeHost.Addrs()[0], edgeHost.ID())
	origin1Node, err := dialer.NewOriginNode(ctx, dialer.Config{
		Host:          origin1Host,
		Authenticator: origin1Auth,
		Registry:      origin1Registry,
		Routes:        origin1Routes,
		OriginKey:     originMasterKey,
		EdgeAddrs:     []string{edgeMultiaddrStr},
		Services: []dialer.ServiceConfig{
			{
				ServiceID:  "pbx-core",
				Protocol:   control.TransportProtocol_TCP,
				PublicPort: publicPort,
				Policy:     control.RoutingPolicy_STRICT_SINGLETON,
				Target:     backendAddr,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create origin1 node: %v", err)
	}
	origin1Node.Start()

	// Wait for registration on Edge
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
		t.Fatalf("service failed to register on edge within timeout")
	}

	edgeTarget := fmt.Sprintf("127.0.0.1:%d", publicPort)

	// 4. Verify client can connect and echo traffic
	clientConn, err := net.DialTimeout("tcp", edgeTarget, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial edge target: %v", err)
	}

	testMsg := []byte("singleton-health-check")
	if _, err := clientConn.Write(testMsg); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	buf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf) != string(testMsg) {
		t.Fatalf("mismatch: got %s", buf)
	}
	clientConn.Close()

	// 5. Kill Origin 1
	origin1Node.Close()
	origin1Host.Close()

	// Wait for Edge to detect disconnect and evict peer
	deadline = time.Now().Add(3 * time.Second)
	closed := false
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", edgeTarget, 100*time.Millisecond)
		if err != nil {
			closed = true
			break
		}
		conn.Close()
		time.Sleep(100 * time.Millisecond)
	}

	if !closed {
		t.Fatal("expected Edge to immediately close listener and fail-closed after singleton origin died")
	}
}
