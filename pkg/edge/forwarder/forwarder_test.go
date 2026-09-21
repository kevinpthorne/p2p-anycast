package forwarder

import (
	"bytes"
	"net"
	"testing"
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
