package forwarder

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestForwardEnvelopeEncodeDecode(t *testing.T) {
	var bindingID [16]byte
	copy(bindingID[:], "binding-token-01")
	var hmacToken [16]byte
	copy(hmacToken[:], "hmac-auth-token1")

	env := &ForwardEnvelope{
		BindingID:  bindingID,
		HMACToken:  hmacToken,
		FlowID:     42,
		ClientIP:   net.ParseIP("192.0.2.100"),
		ClientPort: 5060,
		Flags:      0,
		Payload:    []byte("SIP/2.0 REGISTER sip:example.com"),
	}

	encoded := env.Encode()
	if len(encoded) != ForwardHeaderSize+len(env.Payload) {
		t.Fatalf("expected encoded length %d, got %d", ForwardHeaderSize+len(env.Payload), len(encoded))
	}

	decoded, err := DecodeForwardEnvelope(encoded)
	if err != nil {
		t.Fatalf("DecodeForwardEnvelope failed: %v", err)
	}

	if decoded.FlowID != env.FlowID {
		t.Fatalf("flow ID mismatch: expected %d, got %d", env.FlowID, decoded.FlowID)
	}
	if decoded.ClientPort != env.ClientPort {
		t.Fatalf("client port mismatch: expected %d, got %d", env.ClientPort, decoded.ClientPort)
	}
	if !bytes.Equal(decoded.Payload, env.Payload) {
		t.Fatalf("payload mismatch: expected %s, got %s", env.Payload, decoded.Payload)
	}
}

func TestReturnEnvelopeEncodeDecode(t *testing.T) {
	env := &ReturnEnvelope{
		FlowID:  1001,
		Payload: []byte("SIP/2.0 200 OK"),
	}

	encoded := env.Encode()
	if len(encoded) != ReturnHeaderSize+len(env.Payload) {
		t.Fatalf("expected length %d, got %d", ReturnHeaderSize+len(env.Payload), len(encoded))
	}

	decoded, err := DecodeReturnEnvelope(encoded)
	if err != nil {
		t.Fatalf("DecodeReturnEnvelope failed: %v", err)
	}

	if decoded.FlowID != env.FlowID {
		t.Fatalf("flow ID mismatch: expected %d, got %d", env.FlowID, decoded.FlowID)
	}
	if !bytes.Equal(decoded.Payload, env.Payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestHandleReturnDatagramFromPeerOriginVerification(t *testing.T) {
	fm := NewEdgeDatagramForwarder(context.Background(), nil)
	defer fm.Close()

	listenerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to create listener UDP: %v", err)
	}
	defer listenerConn.Close()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to create client UDP: %v", err)
	}
	defer clientConn.Close()

	legitOrigin := peer.ID("origin-legit")
	spoofOrigin := peer.ID("origin-spoof")
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)

	// Register flow bound to legitOrigin
	var flowID uint32 = 0xCAFE1234
	cf := &clientFlow{
		flowID:     flowID,
		flowKey:    buildFlowKey(listenerConn, clientAddr),
		clientAddr: clientAddr,
		listener:   listenerConn,
		originPeer: legitOrigin,
	}
	cf.touch()
	fm.mu.Lock()
	fm.flowsByID[flowID] = cf
	fm.mu.Unlock()

	retEnv := (&ReturnEnvelope{
		FlowID:  flowID,
		Payload: []byte("RETURN-PAYLOAD"),
	}).Encode()

	// 1. Return datagram from spoofOrigin MUST be rejected
	if err := fm.HandleReturnDatagramFromPeer(spoofOrigin, retEnv); err == nil {
		t.Fatal("expected HandleReturnDatagramFromPeer from spoofOrigin to fail")
	}

	// 2. Return datagram from legitOrigin MUST succeed and deliver to clientConn
	if err := fm.HandleReturnDatagramFromPeer(legitOrigin, retEnv); err != nil {
		t.Fatalf("HandleReturnDatagramFromPeer from legitOrigin failed: %v", err)
	}

	buf := make([]byte, 128)
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := clientConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client failed to receive return datagram: %v", err)
	}
	if string(buf[:n]) != "RETURN-PAYLOAD" {
		t.Fatalf("unexpected payload: %s", string(buf[:n]))
	}
}
