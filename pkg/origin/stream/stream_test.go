package stream

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2p-anycast/pkg/control/binding"
	control "p2p-anycast/pkg/proto/control"
	"p2p-anycast/pkg/edge/proxy"
	"p2p-anycast/pkg/origin/dispatch"
	"p2p-anycast/pkg/pki/keystore"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

func TestOriginStreamPiping(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	originKey := []byte("origin-test-secret-key-32-bytes")

	// 1. Mock TCP backend server (echo)
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on backend: %v", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Setup Origin Host and Handler
	originIdKey, _ := keystore.LoadOrGenerateIdentity(keystore.Options{ForceTier: keystore.TierRAM})
	originHost, err := p2pquic.NewHost(ctx, originIdKey, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create origin host: %v", err)
	}
	defer originHost.Close()

	table := dispatch.NewTable()
	bID := binding.DeriveBindingID("echo-svc", control.TransportProtocol_TCP, 9000, "")
	table.AddRoute(dispatch.Route{
		BindingID:  bID,
		Target:     backendAddr,
		Protocol:   control.TransportProtocol_TCP,
		PublicPort: 9000,
		ServiceID:  "echo-svc",
	})

	_ = NewHandler(originHost, originKey, table)

	// 3. Setup Edge Host
	edgeIdKey, _ := keystore.LoadOrGenerateIdentity(keystore.Options{ForceTier: keystore.TierRAM})
	edgeHost, err := p2pquic.NewHost(ctx, edgeIdKey, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create edge host: %v", err)
	}
	defer edgeHost.Close()

	if err := edgeHost.Connect(ctx, peer.AddrInfo{ID: originHost.ID(), Addrs: originHost.Addrs()}); err != nil {
		t.Fatalf("failed to connect edge to origin: %v", err)
	}

	// 4. Edge opens stream and sends preamble + data
	s, err := edgeHost.NewStream(ctx, originHost.ID(), proxy.TCPProtocolID)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	defer s.Close()

	token := binding.GenerateHMAC(originKey, edgeHost.ID().String(), 9000, bID)

	var preamble [32]byte
	copy(preamble[0:16], bID[:])
	copy(preamble[16:32], token[:])

	if _, err := s.Write(preamble[:]); err != nil {
		t.Fatalf("failed to write preamble: %v", err)
	}

	testPayload := []byte("ping pong stream test 123")
	if _, err := s.Write(testPayload); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	// Read echoed response
	resp := make([]byte, len(testPayload))
	if _, err := io.ReadFull(s, resp); err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if !bytes.Equal(resp, testPayload) {
		t.Fatalf("echo mismatch: got %s", resp)
	}
}
