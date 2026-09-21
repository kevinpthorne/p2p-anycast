package test

import (
	"context"
	"crypto/tls"
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
	edgeKey, _ := keystore.LoadOrGenerateIdentity(keystore.Options{ForceTier: keystore.TierRAM})
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

	edgeRouter = ingress.NewRouter(ctx, edgeHost, leaseMgr)
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
			ServicePattern: "web-*",
			AllowedPolicies: []identity.AuthorizedPolicy{
				identity.AuthorizedPolicy_POLICY_TLS_SNI,
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
				Policy:      control.RoutingPolicy_TLS_SNI,
				SNIHostname: site1Host,
				Target:      tlsAddr1,
			},
			{
				ServiceID:   "web-app2",
				Protocol:    control.TransportProtocol_TCP,
				PublicPort:  publicPort,
				Policy:      control.RoutingPolicy_TLS_SNI,
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
