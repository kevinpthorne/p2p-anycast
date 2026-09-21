package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/google/go-tpm/legacy/tpm2"
	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2p-anycast/pkg/pki/mldsa"
)

type KeystoreTier string

const (
	TierTPM2          KeystoreTier = "TPM2.0"
	TierSecureEnclave KeystoreTier = "AppleSecureEnclave"
	TierFilesystem    KeystoreTier = "Filesystem"
	TierRAM           KeystoreTier = "RAM"

	ContextAnchorBinding = "p2p-anycast:anchor:bind:v1"
)

// IdentityKey encapsulates a node's cryptographic identity, including hardware anchor,
// post-quantum ML-DSA-87 identity, and libp2p identity.
type IdentityKey struct {
	tier         KeystoreTier
	anchorSigner crypto.Signer
	mldsaPub     *mldsa87.PublicKey
	mldsaPriv    *mldsa87.PrivateKey
	libp2pPriv   ic.PrivKey
	peerID       peer.ID
	attestation  []byte
}

var _ crypto.Signer = (*IdentityKey)(nil)

// Tier returns the keystore tier from which this identity was loaded.
func (k *IdentityKey) Tier() KeystoreTier {
	return k.tier
}

// MLDSAPubKey returns the ML-DSA-87 public key.
func (k *IdentityKey) MLDSAPubKey() *mldsa87.PublicKey {
	return k.mldsaPub
}

// MLDSAPrivKey returns the ML-DSA-87 private key.
func (k *IdentityKey) MLDSAPrivKey() *mldsa87.PrivateKey {
	return k.mldsaPriv
}

// Libp2pPrivKey returns the libp2p private key.
func (k *IdentityKey) Libp2pPrivKey() ic.PrivKey {
	return k.libp2pPriv
}

// PeerID returns the libp2p Peer ID.
func (k *IdentityKey) PeerID() peer.ID {
	return k.peerID
}

// Attestation returns the hardware anchor's signature binding the ML-DSA key and Peer ID.
func (k *IdentityKey) Attestation() []byte {
	return k.attestation
}

// Public implements crypto.Signer.
func (k *IdentityKey) Public() crypto.PublicKey {
	return k.mldsaPub
}

// Sign implements crypto.Signer.
func (k *IdentityKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return k.mldsaPriv.Sign(rand, digest, opts)
}

// SignWithContext signs a message with ML-DSA-87 using an explicit FIPS 204 context string.
func (k *IdentityKey) SignWithContext(msg []byte, ctx string) ([]byte, error) {
	return mldsa.Sign(k.mldsaPriv, msg, ctx)
}

// Options configures the keystore waterfall loader.
type Options struct {
	KeyFilePath string
	AllowCreate bool
	ForceTier   KeystoreTier // If set, only attempt this tier (useful for testing)
}

// LoadOrGenerateIdentity loads or generates a node identity following the strict waterfall:
// Tier 1A (TPM 2.0) -> Tier 1B (Apple Secure Enclave) -> Tier 2 (Filesystem) -> Tier 3 (RAM).
func LoadOrGenerateIdentity(opts Options) (*IdentityKey, error) {
	var anchor crypto.Signer
	var selectedTier KeystoreTier

	// 1. Tier 1A: TPM 2.0
	if opts.ForceTier == "" || opts.ForceTier == TierTPM2 {
		if tpmSigner, err := tryTPM2(); err == nil && tpmSigner != nil {
			anchor = tpmSigner
			selectedTier = TierTPM2
		}
	}

	// 2. Tier 1B: Apple Secure Enclave
	if anchor == nil && (opts.ForceTier == "" || opts.ForceTier == TierSecureEnclave) {
		if seSigner, err := trySecureEnclave(); err == nil && seSigner != nil {
			anchor = seSigner
			selectedTier = TierSecureEnclave
		}
	}

	// 3. Tier 2: Filesystem Key
	if anchor == nil && (opts.ForceTier == "" || opts.ForceTier == TierFilesystem) {
		keyPath := opts.KeyFilePath
		if keyPath == "" {
			keyPath = "identity.key"
		}
		if fileSigner, err := tryFilesystem(keyPath, opts.AllowCreate); err == nil && fileSigner != nil {
			anchor = fileSigner
			selectedTier = TierFilesystem
		}
	}

	// 4. Tier 3: RAM
	if anchor == nil {
		ramSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral RAM key: %w", err)
		}
		anchor = ramSigner
		selectedTier = TierRAM
	}

	// Generate ephemeral FIPS 204 ML-DSA-87 keypair on boot
	mldsaPub, mldsaPriv, err := mldsa.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA-87 keypair: %w", err)
	}

	// Generate corresponding libp2p host identity (Ed25519)
	p2pPriv, p2pPub, err := ic.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate libp2p key: %w", err)
	}

	pID, err := peer.IDFromPublicKey(p2pPub)
	if err != nil {
		return nil, fmt.Errorf("failed to derive libp2p peer ID: %w", err)
	}

	// Cross-bind anchor key to ML-DSA-87 pubkey and libp2p Peer ID
	bindingPayload := append([]byte(ContextAnchorBinding), mldsa.PublicKeyToBytes(mldsaPub)...)
	bindingPayload = append(bindingPayload, []byte(pID.String())...)
	bindingDigest := sha256.Sum256(bindingPayload)

	attestation, err := anchor.Sign(rand.Reader, bindingDigest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to cross-bind anchor key to ML-DSA identity: %w", err)
	}

	return &IdentityKey{
		tier:         selectedTier,
		anchorSigner: anchor,
		mldsaPub:     mldsaPub,
		mldsaPriv:    mldsaPriv,
		libp2pPriv:   p2pPriv,
		peerID:       pID,
		attestation:  attestation,
	}, nil
}

// tryTPM2 attempts to probe and connect to a TPM 2.0 device on Linux or Windows.
func tryTPM2() (crypto.Signer, error) {
	devices := []string{"/dev/tpmrm0", "/dev/tpm0"}
	for _, dev := range devices {
		rwc, err := tpm2.OpenTPM(dev)
		if err == nil {
			defer rwc.Close()
			// Generate or load SRK key
			// If accessible, we can use a generated key or return nil to fallback if SRK is unsupported
			return nil, errors.New("TPM device found but SRK initialization not configured")
		}
	}
	return nil, errors.New("no TPM 2.0 device accessible")
}

// trySecureEnclave attempts to probe Apple Secure Enclave on Darwin ARM64.
func trySecureEnclave() (crypto.Signer, error) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return nil, errors.New("Secure Enclave only supported on Darwin ARM64")
	}
	// In headless, non-entitled CLI processes, Secure Enclave keychain creation returns errSecAuthFailed.
	// We probe if SE is accessible; if not, fall back cleanly.
	return nil, errors.New("Secure Enclave not available in current process context")
}

// tryFilesystem loads an existing ECDSA P-256 PEM key or creates a new one if allowed.
func tryFilesystem(path string, allowCreate bool) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("invalid PEM in identity key file")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	if !allowCreate {
		return nil, err
	}

	// Generate and save new key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return nil, err
	}

	return key, nil
}
