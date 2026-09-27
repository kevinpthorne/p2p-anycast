package nat

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2p-anycast/pkg/control/binding"
	control "p2p-anycast/pkg/proto/control"
	"p2p-anycast/pkg/edge/forwarder"
	"p2p-anycast/pkg/origin/dispatch"
	"p2p-anycast/pkg/pki/keystore"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

func TestStatefulNATTableAndReaping(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	originKey := []byte("secret-origin-nat-key-32-bytes!")

	// 1. Mock UDP backend service (e.g. echo server on localhost)
	backendConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to bind mock backend: %v", err)
	}
	defer backendConn.Close()

	// Backend echo loop
	go func() {
		buf := make([]byte, 2048)
		for {
			n, clientAddr, err := backendConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = backendConn.WriteToUDP(buf[:n], clientAddr)
		}
	}()

	// 2. Setup Hosts
	originIdKey, _ := keystore.GenerateTestIdentity()
	originHost, err := p2pquic.NewHost(ctx, originIdKey, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create origin host: %v", err)
	}
	defer originHost.Close()

	edgeIdKey, _ := keystore.GenerateTestIdentity()
	edgeHost, err := p2pquic.NewHost(ctx, edgeIdKey, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create edge host: %v", err)
	}
	defer edgeHost.Close()

	if err := edgeHost.Connect(ctx, peer.AddrInfo{ID: originHost.ID(), Addrs: originHost.Addrs()}); err != nil {
		t.Fatalf("failed to connect edge to origin: %v", err)
	}

	// 3. Setup Route Table
	routes := dispatch.NewTable()
	bID := binding.DeriveBindingID("pbx-sip", control.TransportProtocol_UDP, 5060, "")
	routes.AddRoute(dispatch.Route{
		BindingID:  bID,
		Target:     backendConn.LocalAddr().String(),
		Protocol:   control.TransportProtocol_UDP,
		PublicPort: 5060,
		ServiceID:  "pbx-sip",
	})

	// Configure NAT with fast reaper for testing
	reapedChan := make(chan SessionKey, 1)
	natTable := NewTable(ctx, originHost, originKey, routes, Config{
		ReaperInterval: 20 * time.Millisecond,
		OnSessionClosed: func(key SessionKey) {
			reapedChan <- key
		},
	})
	defer natTable.Close()

	// 4. Send Forward Datagram to Origin
	token := binding.GenerateHMAC(originKey, edgeHost.ID().String(), 5060, bID)
	env := &forwarder.ForwardEnvelope{
		BindingID:  bID,
		HMACToken:  token,
		FlowID:     999,
		ClientIP:   net.ParseIP("203.0.113.10"),
		ClientPort: 5060,
		Flags:      0,
		Payload:    []byte("INVITE sip:alice@example.com SIP/2.0"),
	}

	// Origin receives return packet channel
	conns := edgeHost.Network().ConnsToPeer(originHost.ID())
	if len(conns) == 0 {
		t.Fatal("no edge conn to origin")
	}

	returnChan := make(chan []byte, 1)
	go func() {
		data, err := p2pquic.ReceiveDatagram(ctx, conns[0])
		if err == nil {
			returnChan <- data
		}
	}()

	if err := natTable.HandleForwardDatagram(edgeHost.ID(), env.Encode()); err != nil {
		t.Fatalf("HandleForwardDatagram error: %v", err)
	}

	if natTable.ActiveSessionCount() != 1 {
		t.Fatalf("expected 1 active session, got %d", natTable.ActiveSessionCount())
	}

	// 5. Verify return datagram from backend echo arrives
	select {
	case retData := <-returnChan:
		retEnv, err := forwarder.DecodeReturnEnvelope(retData)
		if err != nil {
			t.Fatalf("failed to decode return envelope: %v", err)
		}
		if retEnv.FlowID != 999 {
			t.Fatalf("expected return flow ID 999, got %d", retEnv.FlowID)
		}
		if !bytes.Equal(retEnv.Payload, env.Payload) {
			t.Fatalf("expected payload %q, got %q", env.Payload, retEnv.Payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for return datagram")
	}
}
