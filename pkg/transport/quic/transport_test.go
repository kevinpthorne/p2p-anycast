package quic

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2p-anycast/pkg/pki/keystore"
)

func TestQUICHostAndDatagrams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Create two hosts
	key1, err := keystore.GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}
	h1, err := NewHost(ctx, key1, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create host1: %v", err)
	}
	defer h1.Close()

	key2, err := keystore.GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}
	h2, err := NewHost(ctx, key2, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create host2: %v", err)
	}
	defer h2.Close()

	// 2. Connect h2 to h1
	h1Info := peer.AddrInfo{
		ID:    h1.ID(),
		Addrs: h1.Addrs(),
	}
	if err := h2.Connect(ctx, h1Info); err != nil {
		t.Fatalf("h2 failed to connect to h1: %v", err)
	}

	// 3. Verify ExtractQUICConn
	conns := h2.Network().ConnsToPeer(h1.ID())
	if len(conns) == 0 {
		t.Fatal("no active connection found")
	}
	qconn2, err := ExtractQUICConn(conns[0])
	if err != nil {
		t.Fatalf("failed to extract QUIC conn: %v", err)
	}
	if qconn2 == nil {
		t.Fatal("extracted quic conn is nil")
	}

	// 4. Test Datagram round-trip
	h1Conns := h1.Network().ConnsToPeer(h2.ID())
	if len(h1Conns) == 0 {
		t.Fatal("h1 has no connection to h2")
	}

	testPayload := []byte("voip-rtp-datagram-12345")

	// Start datagram receiver on h1
	recvChan := make(chan []byte, 1)
	errChan := make(chan error, 1)
	go func() {
		data, err := ReceiveDatagram(ctx, h1Conns[0])
		if err != nil {
			errChan <- err
			return
		}
		recvChan <- data
	}()

	// Send from h2 to h1
	if err := SendDatagram(h2, h1.ID(), testPayload); err != nil {
		t.Fatalf("failed to send datagram: %v", err)
	}

	select {
	case received := <-recvChan:
		if !bytes.Equal(received, testPayload) {
			t.Fatalf("datagram mismatch: expected %q, got %q", testPayload, received)
		}
	case err := <-errChan:
		t.Fatalf("receive datagram error: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for datagram")
	}
}
