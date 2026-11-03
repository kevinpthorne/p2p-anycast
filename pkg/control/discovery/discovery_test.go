package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2p-anycast/pkg/pki/keystore"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

func TestEdgeAdvertiserAndDiscoverer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 1. Create Edge A (Host 1, Server DHT, advertiser)
	keyA, err := keystore.GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate key for Edge A: %v", err)
	}
	hA, err := p2pquic.NewHost(ctx, keyA, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create host A: %v", err)
	}
	defer hA.Close()

	advA, err := NewEdgeAdvertiser(ctx, hA, nil, WithAdvertiseInterval(500*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create advertiser A: %v", err)
	}
	defer advA.Close()

	// 2. Create Edge B (Host 2, Server DHT, advertiser bootstrapped to Edge A)
	keyB, err := keystore.GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate key for Edge B: %v", err)
	}
	hB, err := p2pquic.NewHost(ctx, keyB, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create host B: %v", err)
	}
	defer hB.Close()

	edgeAAddrs, err := peer.AddrInfoToP2pAddrs(&peer.AddrInfo{ID: hA.ID(), Addrs: hA.Addrs()})
	if err != nil {
		t.Fatalf("failed to convert edge A addrs: %v", err)
	}

	advB, err := NewEdgeAdvertiser(ctx, hB, edgeAAddrs, WithAdvertiseInterval(500*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create advertiser B: %v", err)
	}
	defer advB.Close()

	// 3. Create Origin (Host 3, Client DHT, discoverer bootstrapped ONLY to Edge A)
	keyO, err := keystore.GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate key for Origin: %v", err)
	}
	hO, err := p2pquic.NewHost(ctx, keyO, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create host Origin: %v", err)
	}
	defer hO.Close()

	discO, err := NewEdgeDiscoverer(ctx, hO)
	if err != nil {
		t.Fatalf("failed to create discoverer Origin: %v", err)
	}
	defer discO.Close()

	if err := discO.Bootstrap(ctx, []peer.AddrInfo{{ID: hA.ID(), Addrs: hA.Addrs()}}); err != nil {
		t.Fatalf("failed to bootstrap discoverer: %v", err)
	}

	// 4. Poll FindEdges until Edge B is discovered via DHT routing
	foundB := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		edgeChan, err := discO.FindEdges(ctx, 10)
		if err != nil {
			t.Fatalf("FindEdges failed: %v", err)
		}

		for p := range edgeChan {
			if p.ID == hB.ID() {
				foundB = true
				break
			}
		}

		if foundB {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}

	if !foundB {
		t.Fatalf("Origin failed to discover Edge B via DHT; routing table did not return Edge B")
	}
}
