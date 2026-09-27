package auth

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2p-anycast/pkg/pki/keystore"
	"p2p-anycast/pkg/pki/manifest"
	"p2p-anycast/pkg/pki/mldsa"
	identity "p2p-anycast/pkg/proto/identity"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

func TestMutualAuthHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Setup Root CA (MLDSA for signing manifests)
	caPub, caPriv, err := mldsa.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	// 2. Setup Edge
	edgeKey, err := keystore.GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate edge key: %v", err)
	}
	edgeHost, err := p2pquic.NewHost(ctx, edgeKey, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create edge host: %v", err)
	}
	defer edgeHost.Close()

	now := time.Now()
	edgeClaims := &identity.IdentityClaims{
		SerialNumber: 1,
		IssuerId:     "root-ca",
		SubjectId:    "edge-vps-01",
		Role:         identity.NodeRole_EDGE_ROUTER,
		Libp2PPeerId: edgeHost.ID().String(),
		NotBefore:    now.Add(-1 * time.Hour).Unix(),
		NotAfter:     now.Add(24 * time.Hour).Unix(),
	}
	edgeManifest, err := manifest.SignManifest(edgeClaims, caPriv, caPub)
	if err != nil {
		t.Fatalf("failed to sign edge manifest: %v", err)
	}

	edgeAuth := NewAuthenticator(edgeHost, edgeKey, edgeManifest, caPub)
	edgeAuth.RegisterStreamHandler()

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

	originClaims := &identity.IdentityClaims{
		SerialNumber: 2,
		IssuerId:     "root-ca",
		SubjectId:    "origin-pbx-01",
		Role:         identity.NodeRole_ORIGIN_NODE,
		Libp2PPeerId: originHost.ID().String(),
		NotBefore:    now.Add(-1 * time.Hour).Unix(),
		NotAfter:     now.Add(24 * time.Hour).Unix(),
	}
	originManifest, err := manifest.SignManifest(originClaims, caPriv, caPub)
	if err != nil {
		t.Fatalf("failed to sign origin manifest: %v", err)
	}

	originAuth := NewAuthenticator(originHost, originKey, originManifest, caPub)

	// 4. Connect Origin to Edge
	edgeInfo := peer.AddrInfo{
		ID:    edgeHost.ID(),
		Addrs: edgeHost.Addrs(),
	}
	if err := originHost.Connect(ctx, edgeInfo); err != nil {
		t.Fatalf("origin failed to connect to edge: %v", err)
	}

	// 5. Run Outbound Authentication from Origin
	verifiedEdgeClaims, err := originAuth.AuthenticateOutbound(ctx, edgeHost.ID())
	if err != nil {
		t.Fatalf("mutual auth failed: %v", err)
	}

	if verifiedEdgeClaims.SubjectId != "edge-vps-01" {
		t.Fatalf("expected edge subject 'edge-vps-01', got %s", verifiedEdgeClaims.SubjectId)
	}

	// Wait briefly for server stream handler to complete session store
	time.Sleep(50 * time.Millisecond)

	verifiedOriginClaims, ok := edgeAuth.GetSession(originHost.ID())
	if !ok {
		t.Fatal("edge did not record authenticated origin session")
	}
	if verifiedOriginClaims.SubjectId != "origin-pbx-01" {
		t.Fatalf("expected origin subject 'origin-pbx-01', got %s", verifiedOriginClaims.SubjectId)
	}
}
