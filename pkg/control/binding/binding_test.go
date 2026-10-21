package binding

import (
	"bytes"
	"testing"

	control "p2p-anycast/pkg/proto/control"
)

func TestDeriveBindingID(t *testing.T) {
	// Must be deterministic
	b1 := DeriveBindingID("pbx-core", control.TransportProtocol_UDP, 5060, "")
	b2 := DeriveBindingID("pbx-core", control.TransportProtocol_UDP, 5060, "")
	if !bytes.Equal(b1[:], b2[:]) {
		t.Fatal("DeriveBindingID is non-deterministic")
	}

	// Different port must change binding_id
	b3 := DeriveBindingID("pbx-core", control.TransportProtocol_UDP, 5061, "")
	if bytes.Equal(b1[:], b3[:]) {
		t.Fatal("DeriveBindingID did not change with different port")
	}

	// Different protocol must change binding_id
	b4 := DeriveBindingID("pbx-core", control.TransportProtocol_TCP, 5060, "")
	if bytes.Equal(b1[:], b4[:]) {
		t.Fatal("DeriveBindingID did not change with different protocol")
	}

	// Different SNI must change binding_id
	b5 := DeriveBindingID("web-svc", control.TransportProtocol_TCP, 443, "app1.example.com")
	b6 := DeriveBindingID("web-svc", control.TransportProtocol_TCP, 443, "app2.example.com")
	if bytes.Equal(b5[:], b6[:]) {
		t.Fatal("DeriveBindingID did not change with different SNI hostname")
	}
}

func TestGenerateAndVerifyHMAC(t *testing.T) {
	originKey := []byte("super-secret-origin-master-key32")
	edgePeerID := "12D3KooWEdgeNodePeerID"
	publicPort := uint32(25565)
	bindingID := DeriveBindingID("minecraft-smp", control.TransportProtocol_TCP, 25565, "")

	token := GenerateHMAC(originKey, edgePeerID, publicPort, bindingID)

	// Valid token passes
	if !VerifyHMAC(originKey, edgePeerID, publicPort, bindingID, token[:]) {
		t.Fatal("VerifyHMAC failed with valid token")
	}

	// Wrong edge peer ID fails
	if VerifyHMAC(originKey, "12D3KooWRandomEdgePeerID", publicPort, bindingID, token[:]) {
		t.Fatal("VerifyHMAC succeeded with wrong Edge peer ID")
	}

	// Wrong port fails
	if VerifyHMAC(originKey, edgePeerID, 8080, bindingID, token[:]) {
		t.Fatal("VerifyHMAC succeeded with wrong port")
	}

	// Wrong binding ID fails
	otherBinding := DeriveBindingID("pbx-core", control.TransportProtocol_UDP, 5060, "")
	if VerifyHMAC(originKey, edgePeerID, publicPort, otherBinding, token[:]) {
		t.Fatal("VerifyHMAC succeeded with wrong binding ID")
	}

	// Wrong key fails
	if VerifyHMAC([]byte("wrong-key"), edgePeerID, publicPort, bindingID, token[:]) {
		t.Fatal("VerifyHMAC succeeded with wrong origin key")
	}

	// Token generated for Edge 1 MUST NOT verify for Edge 2
	edge1Token := GenerateHMAC(originKey, "12D3KooWEdge1", publicPort, bindingID)
	edge2Token := GenerateHMAC(originKey, "12D3KooWEdge2", publicPort, bindingID)
	if bytes.Equal(edge1Token[:], edge2Token[:]) {
		t.Fatal("per-Edge HMAC tokens must be distinct across different Edge peers")
	}
	if !VerifyHMAC(originKey, "12D3KooWEdge1", publicPort, bindingID, edge1Token[:]) {
		t.Fatal("VerifyHMAC failed for Edge1 with Edge1 token")
	}
	if VerifyHMAC(originKey, "12D3KooWEdge2", publicPort, bindingID, edge1Token[:]) {
		t.Fatal("VerifyHMAC succeeded for Edge2 using Edge1 token (cross-Edge replay!)")
	}
}

func TestValidateMasterKey(t *testing.T) {
	// Short key must fail
	if err := ValidateMasterKey([]byte("too-short")); err == nil {
		t.Fatal("expected error for short master key")
	}

	// All-zero 32-byte key must fail
	zeroKey := make([]byte, 32)
	if err := ValidateMasterKey(zeroKey); err == nil {
		t.Fatal("expected error for all-zero master key")
	}

	// Valid 32-byte key must pass
	validKey := []byte("super-secret-origin-master-key32")
	if err := ValidateMasterKey(validKey); err != nil {
		t.Fatalf("expected valid master key to pass, got: %v", err)
	}
}
