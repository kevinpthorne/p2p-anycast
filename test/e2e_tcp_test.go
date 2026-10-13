package test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
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

func TestE2ETCPAndTLSSNIDemuxing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pki := SetupTestPKI(t)
	originMasterKey := []byte("master-secret-for-test-origin32")

	// 1. Start Mock TLS Echo Servers
	site1Host := "app1.meshcast.internal"
	site2Host := "app2.meshcast.internal"

	tlsLn1, tlsAddr1, _ := StartMockTLSEchoServer(t, site1Host)
	defer tlsLn1.Close()

	tlsLn2, tlsAddr2, _ := StartMockTLSEchoServer(t, site2Host)
	defer tlsLn2.Close()

	// 2. Setup Edge Host
	edgeKey, _ := keystore.GenerateTestIdentity()
	edgeHost, err := p2pquic.NewHost(ctx, edgeKey, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create edge host: %v", err)
	}
	defer edgeHost.Close()
	t.Logf("edgeHost Addrs: %v", edgeHost.Addrs())

	edgeManifest := pki.IssueManifest(t, "edge-01", identity.NodeRole_EDGE_ROUTER, edgeKey, nil)
	edgeAuth := auth.NewAuthenticator(edgeHost, edgeKey, edgeManifest, pki.CAPub)
	edgeAuth.RegisterStreamHandler()

	// Reserve a free public port for Edge ingress
	freeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
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

	// 3. Setup Origin Host
	originKey, _ := keystore.GenerateTestIdentity()
	originHost, err := p2pquic.NewHost(ctx, originKey, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create origin host: %v", err)
	}
	defer originHost.Close()

	originCaps := []*identity.ServiceCapability{
		{
			ServicePattern: "web-*",
			AllowedPolicies: []identity.AuthorizedPolicy{
				identity.AuthorizedPolicy_POLICY_CLUSTERED_RTT,
			},
			AllowedPorts: []*identity.PortRange{
				{Start: publicPort, End: publicPort},
			},
		},
	}
	originManifest := pki.IssueManifest(t, "origin-01", identity.NodeRole_ORIGIN_NODE, originKey, originCaps)
	originAuth := auth.NewAuthenticator(originHost, originKey, originManifest, pki.CAPub)

	originRoutes := dispatch.NewTable()
	_ = stream.NewHandler(originHost, originMasterKey, originRoutes)

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
		OriginKey:     originMasterKey,
		EdgeAddrs:     []string{edgeMultiaddrStr},
		Services: []dialer.ServiceConfig{
			{
				ServiceID:   "web-app1",
				Protocol:    control.TransportProtocol_TCP,
				PublicPort:  publicPort,
				Policy:      control.RoutingPolicy_CLUSTERED_RTT,
				SNIHostname: site1Host,
				Target:      tlsAddr1,
			},
			{
				ServiceID:   "web-app2",
				Protocol:    control.TransportProtocol_TCP,
				PublicPort:  publicPort,
				Policy:      control.RoutingPolicy_CLUSTERED_RTT,
				SNIHostname: site2Host,
				Target:      tlsAddr2,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to initialize origin node: %v", err)
	}
	defer originNode.Close()
	originNode.Start()

	// Wait for registration to propagate to edge
	deadline := time.Now().Add(6 * time.Second)
	registered := false
	for time.Now().Before(deadline) {
		if len(leaseMgr.GetRegistrationsForPort(publicPort)) >= 2 {
			registered = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !registered {
		t.Fatalf("services failed to register on edge within timeout (got %d)", len(leaseMgr.GetRegistrationsForPort(publicPort)))
	}

	edgeTarget := fmt.Sprintf("127.0.0.1:%d", publicPort)

	// 4. Test Client 1 connecting with SNI = site1Host
	tlsClient1, err := tls.Dial("tcp", edgeTarget, &tls.Config{
		ServerName:         site1Host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("failed to connect client 1 to edge: %v", err)
	}
	defer tlsClient1.Close()

	msg1 := []byte("Hello App 1 via Edge SNI!")
	if _, err := tlsClient1.Write(msg1); err != nil {
		t.Fatalf("client 1 write failed: %v", err)
	}
	buf1 := make([]byte, len(msg1))
	if _, err := io.ReadFull(tlsClient1, buf1); err != nil {
		t.Fatalf("client 1 read failed: %v", err)
	}
	if string(buf1) != string(msg1) {
		t.Fatalf("echo mismatch for app 1: got %s", buf1)
	}

	// 5. Test Client 2 connecting with SNI = site2Host on the SAME public port!
	tlsClient2, err := tls.Dial("tcp", edgeTarget, &tls.Config{
		ServerName:         site2Host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("failed to connect client 2 to edge: %v", err)
	}
	defer tlsClient2.Close()

	msg2 := []byte("Hello App 2 via Edge SNI!")
	if _, err := tlsClient2.Write(msg2); err != nil {
		t.Fatalf("client 2 write failed: %v", err)
	}
	buf2 := make([]byte, len(msg2))
	if _, err := io.ReadFull(tlsClient2, buf2); err != nil {
		t.Fatalf("client 2 read failed: %v", err)
	}
	if string(buf2) != string(msg2) {
		t.Fatalf("echo mismatch for app 2: got %s", buf2)
	}

	// 6. Test Unrecognized SNI -> Must fail handshake / reset
	tlsClientBad, err := tls.Dial("tcp", edgeTarget, &tls.Config{
		ServerName:         "unregistered.example.com",
		InsecureSkipVerify: true,
	})
	if err == nil {
		_, readErr := tlsClientBad.Write([]byte("bad request"))
		if readErr == nil {
			var b [10]byte
			_, readErr = tlsClientBad.Read(b[:])
		}
		if readErr == nil {
			t.Fatal("expected connection to fail for unregistered SNI, but succeeded")
		}
		tlsClientBad.Close()
	}
}

func TestE2ETLSSNIClusteredOrigins(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pki := SetupTestPKI(t)
	originMasterKey := []byte("master-secret-for-test-origin32")

	// 1. Start Two Mock TLS Echo Servers with the SAME SNI hostname
	clusteredHost := "cluster.meshcast.internal"
	tlsLn1, tlsAddr1, _ := StartMockTLSEchoServer(t, clusteredHost)
	defer tlsLn1.Close()

	tlsLn2, tlsAddr2, _ := StartMockTLSEchoServer(t, clusteredHost)
	defer tlsLn2.Close()

	// 2. Setup Edge Host
	edgeKey, _ := keystore.GenerateTestIdentity()
	edgeHost, err := p2pquic.NewHost(ctx, edgeKey, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create edge host: %v", err)
	}
	defer edgeHost.Close()

	edgeManifest := pki.IssueManifest(t, "edge-01", identity.NodeRole_EDGE_ROUTER, edgeKey, nil)
	edgeAuth := auth.NewAuthenticator(edgeHost, edgeKey, edgeManifest, pki.CAPub)
	edgeAuth.RegisterStreamHandler()

	freeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
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

	edgeHost.Network().Notify(&network.NotifyBundle{
		DisconnectedF: func(net network.Network, conn network.Conn) {
			pID := conn.RemotePeer().String()
			evicted := leaseMgr.EvictPeer(pID)
			for _, reg := range evicted {
				edgeRouter.SyncPortListener(reg.PublicPort)
			}
		},
	})

	_, err = gossip.NewMeshRegistry(ctx, edgeHost, func(reg *control.ServiceRegistration) {
		pID, _ := peer.Decode(reg.OriginPeerId)
		if _, ok := edgeAuth.GetSession(pID); ok {
			_ = leaseMgr.Register(reg)
		}
	})
	if err != nil {
		t.Fatalf("failed to create edge registry: %v", err)
	}

	edgeMultiaddrStr := fmt.Sprintf("%s/p2p/%s", edgeHost.Addrs()[0], edgeHost.ID())

	// Helper to spawn an origin node
	spawnOrigin := func(name string, targetAddr string) (host.Host, *dialer.OriginNode) {
		key, _ := keystore.GenerateTestIdentity()
		host, err := p2pquic.NewHost(ctx, key, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
		if err != nil {
			t.Fatalf("failed to create origin host: %v", err)
		}

		caps := []*identity.ServiceCapability{
			{
				ServicePattern: "web-*",
				AllowedPolicies: []identity.AuthorizedPolicy{
					identity.AuthorizedPolicy_POLICY_CLUSTERED_RTT,
				},
				AllowedPorts: []*identity.PortRange{
					{Start: publicPort, End: publicPort},
				},
			},
		}
		manifest := pki.IssueManifest(t, name, identity.NodeRole_ORIGIN_NODE, key, caps)
		originAuth := auth.NewAuthenticator(host, key, manifest, pki.CAPub)

		routes := dispatch.NewTable()
		_ = stream.NewHandler(host, originMasterKey, routes)

		reg, err := gossip.NewMeshRegistry(ctx, host, nil)
		if err != nil {
			t.Fatalf("failed to create origin registry: %v", err)
		}

		node, err := dialer.NewOriginNode(ctx, dialer.Config{
			Host:          host,
			Authenticator: originAuth,
			Registry:      reg,
			Routes:        routes,
			OriginKey:     originMasterKey,
			EdgeAddrs:     []string{edgeMultiaddrStr},
			Services: []dialer.ServiceConfig{
				{
					ServiceID:   "web-clustered",
					Protocol:    control.TransportProtocol_TCP,
					PublicPort:  publicPort,
					Policy:      control.RoutingPolicy_CLUSTERED_RTT,
					SNIHostname: clusteredHost,
					Target:      targetAddr,
				},
			},
		})
		if err != nil {
			t.Fatalf("failed to init origin node: %v", err)
		}
		node.Start()
		return host, node
	}

	// 3. Start Origin 1 and Origin 2
	host1, node1 := spawnOrigin("origin-01", tlsAddr1)
	defer host1.Close()
	defer node1.Close()

	host2, node2 := spawnOrigin("origin-02", tlsAddr2)
	defer host2.Close()
	defer node2.Close()

	// Wait for registrations to propagate to edge (must be >= 2 for the same port!)
	deadline := time.Now().Add(6 * time.Second)
	registeredBoth := false
	for time.Now().Before(deadline) {
		if len(leaseMgr.GetRegistrationsForPort(publicPort)) >= 2 {
			registeredBoth = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !registeredBoth {
		t.Fatalf("both origins failed to register on edge within timeout (got %d)", len(leaseMgr.GetRegistrationsForPort(publicPort)))
	}

	edgeTarget := fmt.Sprintf("127.0.0.1:%d", publicPort)

	// 4. Test Client connects with SNI = clusteredHost: verify connection succeeds and echoes
	tlsClient, err := tls.Dial("tcp", edgeTarget, &tls.Config{
		ServerName:         clusteredHost,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("failed to connect client to edge for clustered SNI: %v", err)
	}

	msg := []byte("Hello Clustered TLS SNI Origin!")
	if _, err := tlsClient.Write(msg); err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(tlsClient, buf); err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %s", buf)
	}
	tlsClient.Close()

	// 5. Simulate Origin 1 terminating: close node1 and host1
	node1.Close()
	host1.Close()

	// Wait for edge to detect disconnection and evict Origin 1
	deadlineEvict := time.Now().Add(5 * time.Second)
	evictedOne := false
	for time.Now().Before(deadlineEvict) {
		if len(leaseMgr.GetRegistrationsForPort(publicPort)) == 1 {
			evictedOne = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !evictedOne {
		t.Fatalf("origin 1 was not evicted upon disconnect (remaining: %d)", len(leaseMgr.GetRegistrationsForPort(publicPort)))
	}

	// 6. Connect again: traffic must seamlessly route to surviving Origin 2 without fail!
	tlsClient2, err := tls.Dial("tcp", edgeTarget, &tls.Config{
		ServerName:         clusteredHost,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("failed to connect to surviving origin: %v", err)
	}
	defer tlsClient2.Close()

	msg2 := []byte("Hello Surviving Origin 2!")
	if _, err := tlsClient2.Write(msg2); err != nil {
		t.Fatalf("client2 write failed: %v", err)
	}
	buf2 := make([]byte, len(msg2))
	if _, err := io.ReadFull(tlsClient2, buf2); err != nil {
		t.Fatalf("client2 read failed: %v", err)
	}
	if string(buf2) != string(msg2) {
		t.Fatalf("echo mismatch from surviving origin: got %s", buf2)
	}
}

