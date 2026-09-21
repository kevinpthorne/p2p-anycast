package gossip

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2p-anycast/pkg/pki/keystore"
	control "p2p-anycast/pkg/proto/control"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

func TestMeshRegistryGossip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Create two hosts
	key1, _ := keystore.LoadOrGenerateIdentity(keystore.Options{ForceTier: keystore.TierRAM})
	h1, err := p2pquic.NewHost(ctx, key1, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create host1: %v", err)
	}
	defer h1.Close()

	key2, _ := keystore.LoadOrGenerateIdentity(keystore.Options{ForceTier: keystore.TierRAM})
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
