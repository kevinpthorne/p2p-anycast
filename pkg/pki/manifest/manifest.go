package manifest

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"google.golang.org/protobuf/proto"

	"p2p-anycast/pkg/pki/mldsa"
	identity "p2p-anycast/pkg/proto/identity"
)

var (
	ErrInvalidManifest      = errors.New("manifest is nil or corrupted")
	ErrMismatchedCAKeyID    = errors.New("manifest CA key ID does not match trusted Root CA")
	ErrInvalidCASignature   = errors.New("invalid ML-DSA-87 signature from Root CA")
	ErrManifestExpired      = errors.New("manifest validity period has expired")
	ErrManifestNotYetValid  = errors.New("manifest is not yet valid")
	ErrUnauthorizedRole     = errors.New("node role not authorized")
	ErrUnauthorizedPolicy   = errors.New("policy not authorized by manifest capabilities")
	ErrUnauthorizedPort     = errors.New("port not authorized by manifest capabilities")
	ErrUnauthorizedService  = errors.New("service pattern not authorized by manifest capabilities")
)

// ComputeKeyID computes the 32-byte SHA-256 hash of an ML-DSA-87 public key.
func ComputeKeyID(pk *mldsa87.PublicKey) []byte {
	pubBytes := mldsa.PublicKeyToBytes(pk)
	h := sha256.Sum256(pubBytes)
	return h[:]
}

// SignManifest deterministically serializes IdentityClaims and signs it with the Root CA private key.
func SignManifest(claims *identity.IdentityClaims, caPriv *mldsa87.PrivateKey, caPub *mldsa87.PublicKey) (*identity.SignedCapabilityManifest, error) {
	if claims == nil || caPriv == nil || caPub == nil {
		return nil, errors.New("claims, caPriv, and caPub must not be nil")
	}

	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims deterministically: %w", err)
	}

	sig, err := mldsa.Sign(caPriv, payload, mldsa.ContextCAManifest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign claims with CA private key: %w", err)
	}

	keyID := ComputeKeyID(caPub)

	return &identity.SignedCapabilityManifest{
		ClaimsPayload: payload,
		CaSignature:   sig,
		CaKeyId:       keyID,
	}, nil
}

// LoadManifestFile reads a manifest from a file path.
// It accepts both raw binary protobuf (.pb) and base64-encoded text (.pb64 or inline string).
func LoadManifestFile(path string) (*identity.SignedCapabilityManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest file %s: %w", path, err)
	}
	return LoadManifest(data)
}

// LoadManifest decodes a SignedCapabilityManifest from raw bytes.
// It auto-detects base64-encoded text (strips whitespace first) vs raw binary proto.
func LoadManifest(data []byte) (*identity.SignedCapabilityManifest, error) {
	trimmed := strings.TrimSpace(string(data))
	if isBase64(trimmed) {
		decoded, err := base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
		data = decoded
	}
	var m identity.SignedCapabilityManifest
	if err := proto.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}
	return &m, nil
}

// isBase64 reports whether s looks like a base64-encoded string
// (only contains base64 alphabet characters and padding).
func isBase64(s string) bool {
	if len(s) == 0 || len(s)%4 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

// VerifyManifest validates the CA signature, CA key ID, and validity window of a SignedCapabilityManifest.
func VerifyManifest(manifest *identity.SignedCapabilityManifest, trustedCAPub *mldsa87.PublicKey) (*identity.IdentityClaims, error) {
	if manifest == nil || len(manifest.ClaimsPayload) == 0 || len(manifest.CaSignature) == 0 {
		return nil, ErrInvalidManifest
	}
	if trustedCAPub == nil {
		return nil, errors.New("trusted CA public key must not be nil")
	}

	expectedKeyID := ComputeKeyID(trustedCAPub)
	if len(manifest.CaKeyId) != len(expectedKeyID) {
		return nil, ErrMismatchedCAKeyID
	}
	for i := range expectedKeyID {
		if manifest.CaKeyId[i] != expectedKeyID[i] {
			return nil, ErrMismatchedCAKeyID
		}
	}

	if !mldsa.Verify(trustedCAPub, manifest.ClaimsPayload, mldsa.ContextCAManifest, manifest.CaSignature) {
		return nil, ErrInvalidCASignature
	}

	claims := new(identity.IdentityClaims)
	if err := proto.Unmarshal(manifest.ClaimsPayload, claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	now := time.Now().Unix()
	if now < claims.NotBefore {
		return nil, ErrManifestNotYetValid
	}
	if now > claims.NotAfter {
		return nil, ErrManifestExpired
	}

	return claims, nil
}

// CanAuthorizeService checks whether the given serviceID, publicPort, and policy are authorized by the claims.
func CanAuthorizeService(claims *identity.IdentityClaims, serviceID string, publicPort uint32, policy identity.AuthorizedPolicy) error {
	if claims == nil {
		return errors.New("nil claims")
	}

	matchedService := false
	matchedPort := false
	matchedPolicy := false

	for _, cap := range claims.Capabilities {
		matchedPattern, err := path.Match(cap.ServicePattern, serviceID)
		if err != nil || !matchedPattern {
			continue
		}
		matchedService = true

		portOk := false
		for _, pr := range cap.AllowedPorts {
			if publicPort >= pr.Start && publicPort <= pr.End {
				portOk = true
				break
			}
		}
		if portOk {
			matchedPort = true
		}

		policyOk := false
		for _, p := range cap.AllowedPolicies {
			if p == policy {
				policyOk = true
				break
			}
		}
		if policyOk {
			matchedPolicy = true
		}

		if portOk && policyOk {
			return nil
		}
	}

	if !matchedService {
		return fmt.Errorf("%w: service %q does not match allowed patterns", ErrUnauthorizedService, serviceID)
	}
	if !matchedPort {
		return fmt.Errorf("%w: port %d not in allowed ranges for service %q", ErrUnauthorizedPort, publicPort, serviceID)
	}
	if !matchedPolicy {
		return fmt.Errorf("%w: policy %v not in allowed policies for service %q", ErrUnauthorizedPolicy, policy, serviceID)
	}

	return ErrUnauthorizedPolicy
}
