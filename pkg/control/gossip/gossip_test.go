package gossip

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	"p2p-anycast/pkg/pki/keystore"
	control "p2p-anycast/pkg/proto/control"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

func TestMeshRegistryGossip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Create two hosts
	key1, _ := keystore.GenerateTestIdentity()
	h1, err := p2pquic.NewHost(ctx, key1, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create host1: %v", err)
	}
	defer h1.Close()

	key2, _ := keystore.GenerateTestIdentity()
	h2, err := p2pquic.NewHost(ctx, key2, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create host2: %v", err)
	}
	defer h2.Close()

	// Connect h2 to h1
	if err := h2.Connect(ctx, peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()}); err != nil {
		t.Fatalf("failed to connect h2 to h1: %v", err)
	}

	// 2. Set up MeshRegistry on both
	receivedChan := make(chan *control.ServiceRegistration, 1)
	reg1, err := NewMeshRegistry(ctx, h1, func(reg *control.ServiceRegistration) {
		receivedChan <- reg
	})
	if err != nil {
		t.Fatalf("failed to create registry1: %v", err)
	}
	defer reg1.Close()

	reg2, err := NewMeshRegistry(ctx, h2, nil)
	if err != nil {
		t.Fatalf("failed to create registry2: %v", err)
	}
	defer reg2.Close()

	// Give GossipSub mesh time to exchange heartbeat/mesh links
	time.Sleep(200 * time.Millisecond)

	// 3. Publish announcement from h2
	expectedReg := &control.ServiceRegistration{
		Type:             control.MessageType_ANNOUNCE,
		BindingId:        []byte("gossip-token-123"),
		ServiceId:        "minecraft-smp",
		OriginPeerId:     h2.ID().String(),
		PublicPort:       25565,
		Protocol:         control.TransportProtocol_TCP,
		Policy:           control.RoutingPolicy_CLUSTERED_RTT,
		LeaseDurationSec: 60,
	}

	if err := reg2.Publish(ctx, expectedReg); err != nil {
		t.Fatalf("failed to publish: %v", err)
	}

	select {
	case received := <-receivedChan:
		if !bytes.Equal(received.BindingId, expectedReg.BindingId) {
			t.Fatalf("received binding ID mismatch: %v vs %v", received.BindingId, expectedReg.BindingId)
		}
		if received.ServiceId != expectedReg.ServiceId {
			t.Fatalf("received service ID mismatch: %s", received.ServiceId)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for gossip message")
	}
}

func TestRegistrationSignatureAndTargetEdgeFiltering(t *testing.T) {
	originKey, err := keystore.GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate origin identity: %v", err)
	}
	otherKey, err := keystore.GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate other identity: %v", err)
	}

	reg := &control.ServiceRegistration{
		Type:                 control.MessageType_ANNOUNCE,
		BindingId:            []byte("0123456789abcdef"),
		ServiceId:            "pbx-core",
		OriginPeerId:         originKey.PeerID().String(),
		TargetEdgePeerId:     "12D3KooWTargetEdge1",
		PublicPort:           5060,
		Protocol:             control.TransportProtocol_UDP,
		Policy:               control.RoutingPolicy_STRICT_SINGLETON,
		OriginHmacCapability: []byte("hmac-token-16byt"),
		LeaseDurationSec:     60,
		LeaseEpoch:           1,
	}

	if err := SignRegistration(reg, originKey.Libp2pPrivKey()); err != nil {
		t.Fatalf("SignRegistration failed: %v", err)
	}
	if len(reg.OriginSignature) == 0 || reg.Timestamp == 0 {
		t.Fatal("expected OriginSignature and Timestamp to be populated")
	}

	// Valid signature verification must succeed
	if err := VerifyRegistration(reg); err != nil {
		t.Fatalf("VerifyRegistration failed on valid registration: %v", err)
	}

	// Forging OriginPeerId while signed by another key must fail
	forged := proto.Clone(reg).(*control.ServiceRegistration)
	forged.OriginPeerId = otherKey.PeerID().String()
	if err := VerifyRegistration(forged); err == nil {
		t.Fatal("expected VerifyRegistration to fail when OriginPeerId does not match signing key")
	}

	// Tampering with TargetEdgePeerId or OriginHmacCapability must invalidate signature
	tamperedEdge := proto.Clone(reg).(*control.ServiceRegistration)
	tamperedEdge.TargetEdgePeerId = "12D3KooWTargetEdge2"
	if err := VerifyRegistration(tamperedEdge); err == nil {
		t.Fatal("expected VerifyRegistration to fail when TargetEdgePeerId is modified")
	}
}
func TestRegistrationSignatureECDSA(t *testing.T) {
	originKey, err := keystore.GenerateTestECDSAIdentity()
	if err != nil {
		t.Fatalf("failed to generate ECDSA origin identity: %v", err)
	}
	otherKey, err := keystore.GenerateTestECDSAIdentity()
	if err != nil {
		t.Fatalf("failed to generate other ECDSA identity: %v", err)
	}

	pID := originKey.PeerID()
	if _, err := pID.ExtractPublicKey(); err == nil {
		t.Fatal("expected ExtractPublicKey to fail on ECDSA peer ID (not embedded in multihash)")
	}

	reg := &control.ServiceRegistration{
		Type:                 control.MessageType_ANNOUNCE,
		BindingId:            []byte("0123456789abcdef"),
		ServiceId:            "pbx-core",
		OriginPeerId:         pID.String(),
		TargetEdgePeerId:     "12D3KooWTargetEdge1",
		PublicPort:           5060,
		Protocol:             control.TransportProtocol_UDP,
		Policy:               control.RoutingPolicy_STRICT_SINGLETON,
		OriginHmacCapability: []byte("hmac-token-16byt"),
		LeaseDurationSec:     60,
		LeaseEpoch:           1,
	}

	if err := SignRegistration(reg, originKey.Libp2pPrivKey()); err != nil {
		t.Fatalf("SignRegistration failed on ECDSA key: %v", err)
	}
	if len(reg.OriginSignature) == 0 || reg.Timestamp == 0 {
		t.Fatal("expected OriginSignature and Timestamp to be populated")
	}
	if len(reg.OriginPublicKey) == 0 {
		t.Fatal("expected OriginPublicKey to be populated for non-embedded ECDSA key")
	}

	// 1. Self-contained verification must succeed
	if err := VerifyRegistration(reg); err != nil {
		t.Fatalf("VerifyRegistration failed on valid ECDSA registration: %v", err)
	}

	// 2. Tampered OriginPublicKey must fail
	tamperedPK := proto.Clone(reg).(*control.ServiceRegistration)
	tamperedPK.OriginPublicKey = []byte("corrupted-public-key")
	if err := VerifyRegistration(tamperedPK); err == nil {
		t.Fatal("expected VerifyRegistration to fail on corrupted OriginPublicKey")
	}

	// 3. Spoofed OriginPeerId must fail
	forged := proto.Clone(reg).(*control.ServiceRegistration)
	forged.OriginPeerId = otherKey.PeerID().String()
	if err := VerifyRegistration(forged); err == nil {
		t.Fatal("expected VerifyRegistration to fail when OriginPeerId does not match OriginPublicKey")
	}
}

func TestRegistrationUnupgradedECDSARejection(t *testing.T) {
	originKey, err := keystore.GenerateTestECDSAIdentity()
	if err != nil {
		t.Fatalf("failed to generate ECDSA origin identity: %v", err)
	}

	// Simulate an un-upgraded origin signing without OriginPublicKey
	reg := &control.ServiceRegistration{
		Type:             control.MessageType_ANNOUNCE,
		BindingId:        []byte("0123456789abcdef"),
		ServiceId:        "legacy-svc",
		OriginPeerId:     originKey.PeerID().String(),
		PublicPort:       8080,
		Protocol:         control.TransportProtocol_TCP,
		Policy:           control.RoutingPolicy_CLUSTERED_RTT,
		LeaseDurationSec: 60,
		Timestamp:        time.Now().Unix(),
	}

	payload, err := buildRegistrationSigningPayload(reg)
	if err != nil {
		t.Fatalf("failed to build payload: %v", err)
	}
	sig, err := originKey.Libp2pPrivKey().Sign(payload)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	reg.OriginSignature = sig

	// Verification must fail closed with an explicit error indicating Origin upgrade is required
	err = VerifyRegistration(reg)
	if err == nil {
		t.Fatal("expected VerifyRegistration to fail closed for ECDSA registration lacking OriginPublicKey")
	}
	if !strings.Contains(err.Error(), "origin upgrade required") {
		t.Fatalf("expected error to mention 'origin upgrade required', got: %v", err)
	}
}

func TestMeshRegistryGossipECDSA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Host 1: Edge router
	key1, _ := keystore.GenerateTestIdentity()
	h1, err := p2pquic.NewHost(ctx, key1, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create host1: %v", err)
	}
	defer h1.Close()

	// Host 2: Origin using ECDSA identity (Peer ID starts with Qm...)
	key2, _ := keystore.GenerateTestECDSAIdentity()
	h2, err := p2pquic.NewHost(ctx, key2, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create host2: %v", err)
	}
	defer h2.Close()

	if err := h2.Connect(ctx, peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()}); err != nil {
		t.Fatalf("failed to connect h2 to h1: %v", err)
	}

	receivedChan := make(chan *control.ServiceRegistration, 1)
	reg1, err := NewMeshRegistry(ctx, h1, func(reg *control.ServiceRegistration) {
		receivedChan <- reg
	})
	if err != nil {
		t.Fatalf("failed to create registry1: %v", err)
	}
	defer reg1.Close()

	reg2, err := NewMeshRegistry(ctx, h2, nil)
	if err != nil {
		t.Fatalf("failed to create registry2: %v", err)
	}
	defer reg2.Close()

	time.Sleep(200 * time.Millisecond)

	expectedReg := &control.ServiceRegistration{
		Type:             control.MessageType_ANNOUNCE,
		BindingId:        []byte("gossip-ecdsa-token"),
		ServiceId:        "ecdsa-service",
		OriginPeerId:     h2.ID().String(),
		PublicPort:       5060,
		Protocol:         control.TransportProtocol_UDP,
		Policy:           control.RoutingPolicy_STRICT_SINGLETON,
		LeaseDurationSec: 60,
	}

	if err := reg2.Publish(ctx, expectedReg); err != nil {
		t.Fatalf("failed to publish: %v", err)
	}

	select {
	case received := <-receivedChan:
		if !bytes.Equal(received.BindingId, expectedReg.BindingId) {
			t.Fatalf("received binding ID mismatch: %v vs %v", received.BindingId, expectedReg.BindingId)
		}
		if received.ServiceId != expectedReg.ServiceId {
			t.Fatalf("received service ID mismatch: %s", received.ServiceId)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for gossip message from ECDSA origin")
	}
}
