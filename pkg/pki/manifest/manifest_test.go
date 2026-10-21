package manifest

import (
	"testing"
	"time"

	"p2p-anycast/pkg/pki/mldsa"
	identity "p2p-anycast/pkg/proto/identity"
)

func TestSignAndVerifyManifest(t *testing.T) {
	caPub, caPriv, err := mldsa.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	now := time.Now()
	claims := &identity.IdentityClaims{
		SerialNumber: 1,
		IssuerId:     "root-ca",
		SubjectId:    "origin-node-01",
		Role:         identity.NodeRole_ORIGIN_NODE,
		Libp2PPeerId: "12D3KooWSD5...",
		NotBefore:    now.Add(-1 * time.Hour).Unix(),
		NotAfter:     now.Add(24 * time.Hour).Unix(),
		Capabilities: []*identity.ServiceCapability{
			{
				ServicePattern: "pbx-*",
				AllowedPolicies: []identity.AuthorizedPolicy{
					identity.AuthorizedPolicy_POLICY_STRICT_SINGLETON,
				},
				AllowedPorts: []*identity.PortRange{
					{Start: 5060, End: 5060},
					{Start: 10000, End: 20000},
				},
			},
		},
	}

	// 1. Sign manifest
	signedManifest, err := SignManifest(claims, caPriv, caPub)
	if err != nil {
		t.Fatalf("failed to sign manifest: %v", err)
	}

	// 2. Verify with correct CA
	verifiedClaims, err := VerifyManifest(signedManifest, caPub)
	if err != nil {
		t.Fatalf("manifest verification failed: %v", err)
	}
	if verifiedClaims.SubjectId != "origin-node-01" {
		t.Fatalf("expected subject 'origin-node-01', got %s", verifiedClaims.SubjectId)
	}

	// 3. Verify with wrong CA
	otherPub, _, _ := mldsa.GenerateKey()
	_, err = VerifyManifest(signedManifest, otherPub)
	if err == nil {
		t.Fatal("expected error with untrusted CA, got nil")
	}

	// 4. Test authorization capabilities
	if err := CanAuthorizeService(verifiedClaims, "pbx-core", 5060, identity.AuthorizedPolicy_POLICY_STRICT_SINGLETON); err != nil {
		t.Fatalf("expected authorized, got: %v", err)
	}

	// Disallowed service name
	if err := CanAuthorizeService(verifiedClaims, "minecraft-smp", 25565, identity.AuthorizedPolicy_POLICY_STRICT_SINGLETON); err == nil {
		t.Fatal("expected error for unauthorized service pattern")
	}

	// Disallowed port
	if err := CanAuthorizeService(verifiedClaims, "pbx-core", 8080, identity.AuthorizedPolicy_POLICY_STRICT_SINGLETON); err == nil {
		t.Fatal("expected error for unauthorized port")
	}

	// Disallowed policy
	if err := CanAuthorizeService(verifiedClaims, "pbx-core", 5060, identity.AuthorizedPolicy_POLICY_CLUSTERED_RTT); err == nil {
		t.Fatal("expected error for unauthorized policy")
	}
}

func TestCanAuthorizeServiceWithSNIAndRevocationList(t *testing.T) {
	now := time.Now()
	claims := &identity.IdentityClaims{
		SerialNumber: 42,
		IssuerId:     "root-ca",
		SubjectId:    "origin-web-01",
		Role:         identity.NodeRole_ORIGIN_NODE,
		Libp2PPeerId: "12D3KooWTestPeer",
		NotBefore:    now.Add(-1 * time.Hour).Unix(),
		NotAfter:     now.Add(24 * time.Hour).Unix(),
		Capabilities: []*identity.ServiceCapability{
			{
				ServicePattern: "web-*",
				AllowedPolicies: []identity.AuthorizedPolicy{
					identity.AuthorizedPolicy_POLICY_CLUSTERED_RTT,
				},
				AllowedPorts: []*identity.PortRange{
					{Start: 443, End: 443},
				},
				AllowedSniPatterns: []string{"*.app.example.com", "exact.example.org"},
			},
		},
	}

	// Matching wildcard SNI
	if err := CanAuthorizeServiceWithSNI(claims, "web-frontend", 443, identity.AuthorizedPolicy_POLICY_CLUSTERED_RTT, "portal.app.example.com"); err != nil {
		t.Fatalf("expected wildcard SNI to be authorized, got: %v", err)
	}

	// Matching exact SNI
	if err := CanAuthorizeServiceWithSNI(claims, "web-frontend", 443, identity.AuthorizedPolicy_POLICY_CLUSTERED_RTT, "exact.example.org"); err != nil {
		t.Fatalf("expected exact SNI to be authorized, got: %v", err)
	}

	// Non-matching SNI must be rejected
	if err := CanAuthorizeServiceWithSNI(claims, "web-frontend", 443, identity.AuthorizedPolicy_POLICY_CLUSTERED_RTT, "evil.other.com"); err == nil {
		t.Fatal("expected unauthorized SNI hostname to be rejected")
	}

	// Empty SNI when capability requires AllowedSniPatterns must be rejected
	if err := CanAuthorizeServiceWithSNI(claims, "web-frontend", 443, identity.AuthorizedPolicy_POLICY_CLUSTERED_RTT, ""); err == nil {
		t.Fatal("expected empty SNI to be rejected when capability restricts AllowedSniPatterns")
	}

	// RevocationList checks
	revList := NewRevocationList()
	if revList.IsRevoked(claims) {
		t.Fatal("expected fresh claims not to be revoked")
	}

	revList.RevokeSerial(42)
	if !revList.IsRevoked(claims) {
		t.Fatal("expected claims with serial 42 to be revoked")
	}

	revList2 := NewRevocationList()
	revList2.RevokePeer("12D3KooWTestPeer")
	if !revList2.IsRevoked(claims) {
		t.Fatal("expected claims with peer 12D3KooWTestPeer to be revoked")
	}
}
