package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/go-tpm/legacy/tpm2"
	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type KeystoreTier string

const (
	TierTPM2          KeystoreTier = "TPM2.0"
	TierSecureEnclave KeystoreTier = "AppleSecureEnclave"
	TierFilesystem    KeystoreTier = "Filesystem"
)

// IdentityKey encapsulates a node's cryptographic identity.
// The anchor (TPM/SE/file ECDSA P-256 key) is the authoritative persistent identity.
// The libp2p Peer ID is derived directly from the anchor public key and is therefore
// stable across reboots.
type IdentityKey struct {
	tier       KeystoreTier
	libp2pPriv ic.PrivKey
	peerID     peer.ID
}

// Tier returns the keystore tier from which this identity was loaded.
func (k *IdentityKey) Tier() KeystoreTier {
	return k.tier
}

// Libp2pPrivKey returns the libp2p private key (backed by the anchor key).
func (k *IdentityKey) Libp2pPrivKey() ic.PrivKey {
	return k.libp2pPriv
}

// PeerID returns the libp2p Peer ID (deterministically derived from the anchor public key).
func (k *IdentityKey) PeerID() peer.ID {
	return k.peerID
}

// Options configures the keystore loader.
type Options struct {
	KeyFilePath string       // File path or inline PEM private key string
	AllowCreate bool         // If true and KeyFilePath does not exist, generate and write a new key
	ForceTier   KeystoreTier // If set, only attempt this tier (useful for testing)
}

// LoadOrGenerateIdentity loads or generates a node identity following the anchor waterfall:
// Tier 1A (TPM 2.0) -> Tier 1B (Apple Secure Enclave) -> Tier 2 (Filesystem).
//
// If KeyFilePath is specified, it strictly attempts to load/create the key from that path
// or inline PEM string, returning an error immediately if it cannot be loaded.
//
// The anchor ECDSA P-256 key is used directly as the libp2p identity, so the Peer ID
// is stable and knowable from the public key alone — no ephemeral keys.
func LoadOrGenerateIdentity(opts Options) (*IdentityKey, error) {
	// If KeyFilePath is explicitly specified, or ForceTier is Filesystem, load directly from filesystem / inline PEM.
	if opts.KeyFilePath != "" || opts.ForceTier == TierFilesystem {
		keyPath := opts.KeyFilePath
		if keyPath == "" {
			keyPath = "identity.key"
		}
		fileKey, err := tryFilesystem(keyPath, opts.AllowCreate)
		if err != nil {
			return nil, fmt.Errorf("failed to load identity key (%s): %w", keyPath, err)
		}
		return buildIdentity(fileKey, TierFilesystem)
	}

	// 1. Tier 1A: TPM 2.0
	if opts.ForceTier == "" || opts.ForceTier == TierTPM2 {
		if tpmKey, err := tryTPM2(); err == nil && tpmKey != nil {
			return buildIdentity(tpmKey, TierTPM2)
		} else if opts.ForceTier == TierTPM2 {
			return nil, fmt.Errorf("TPM 2.0 forced but unavailable: %w", err)
		}
	}

	// 2. Tier 1B: Apple Secure Enclave
	if opts.ForceTier == "" || opts.ForceTier == TierSecureEnclave {
		if seKey, err := trySecureEnclave(); err == nil && seKey != nil {
			return buildIdentity(seKey, TierSecureEnclave)
		} else if opts.ForceTier == TierSecureEnclave {
			return nil, fmt.Errorf("Secure Enclave forced but unavailable: %w", err)
		}
	}

	// 3. Check ANYCAST_IDENTITY_KEY env var if set
	if envKey := strings.TrimSpace(os.Getenv("ANYCAST_IDENTITY_KEY")); envKey != "" {
		fileKey, err := tryFilesystem(envKey, opts.AllowCreate)
		if err != nil {
			return nil, fmt.Errorf("failed to load identity key from ANYCAST_IDENTITY_KEY: %w", err)
		}
		return buildIdentity(fileKey, TierFilesystem)
	}

	// 4. Default to identity.key in current working directory
	fileKey, err := tryFilesystem("identity.key", opts.AllowCreate)
	if err != nil {
		return nil, fmt.Errorf("no persistent identity key found (TPM/SE unavailable, and identity.key could not be loaded): %w", err)
	}
	return buildIdentity(fileKey, TierFilesystem)
}

// GenerateTestIdentity generates an ephemeral in-memory ECDSA P-256 identity key for unit tests.
// This is strictly for automated tests and avoids touching the filesystem.
func GenerateTestIdentity() (*IdentityKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate test identity key: %w", err)
	}
	return buildIdentity(key, TierFilesystem)
}

// NewEphemeralIdentity is an alias for GenerateTestIdentity for testing purposes.
func NewEphemeralIdentity() (*IdentityKey, error) {
	return GenerateTestIdentity()
}

// buildIdentity wraps an ECDSA P-256 key as a libp2p identity and derives the Peer ID.
func buildIdentity(key *ecdsa.PrivateKey, tier KeystoreTier) (*IdentityKey, error) {
	p2pPriv, p2pPub, err := ic.ECDSAKeyPairFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap anchor key as libp2p identity: %w", err)
	}

	pID, err := peer.IDFromPublicKey(p2pPub)
	if err != nil {
		return nil, fmt.Errorf("failed to derive Peer ID from anchor public key: %w", err)
	}

	return &IdentityKey{
		tier:       tier,
		libp2pPriv: p2pPriv,
		peerID:     pID,
	}, nil
}

// tryTPM2 attempts to probe and connect to a TPM 2.0 device on Linux or Windows.
func tryTPM2() (*ecdsa.PrivateKey, error) {
	devices := []string{"/dev/tpmrm0", "/dev/tpm0"}
	for _, dev := range devices {
		rwc, err := tpm2.OpenTPM(dev)
		if err == nil {
			defer rwc.Close()
			return nil, errors.New("TPM device found but SRK initialization not configured")
		}
	}
	return nil, errors.New("no TPM 2.0 device accessible")
}

// trySecureEnclave attempts to probe Apple Secure Enclave on Darwin ARM64.
func trySecureEnclave() (*ecdsa.PrivateKey, error) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return nil, errors.New("Secure Enclave only supported on Darwin ARM64")
	}
	return nil, errors.New("Secure Enclave not available in current process context")
}

// tryFilesystem loads an existing ECDSA P-256 key (from file or inline PEM string),
// or creates a new one if allowed. Supports both SEC1 and PKCS#8 PEM formats.
func tryFilesystem(pathOrPEM string, allowCreate bool) (*ecdsa.PrivateKey, error) {
	trimmed := strings.TrimSpace(pathOrPEM)
	if trimmed == "" {
		return nil, errors.New("empty identity key path or data")
	}

	// 1. Check if the string itself is an inline PEM private key
	if strings.Contains(trimmed, "-----BEGIN") {
		return parsePrivateKeyPEM([]byte(trimmed))
	}

	// 2. Read from filesystem path
	data, err := os.ReadFile(trimmed)
	if err == nil {
		return parsePrivateKeyPEM(data)
	}

	// File read failed. Only attempt creation if allowCreate is true and file does not exist.
	if !allowCreate || !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading key file %q: %w", trimmed, err)
	}

	// 3. Generate and save new key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA key: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling EC private key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	if dir := filepath.Dir(trimmed); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("creating directory %q: %w", dir, err)
		}
	}

	if err := os.WriteFile(trimmed, pemBytes, 0600); err != nil {
		return nil, fmt.Errorf("writing key file %q: %w", trimmed, err)
	}

	return key, nil
}

// parsePrivateKeyPEM decodes PEM bytes and parses ECDSA private keys in SEC1 or PKCS#8 format.
func parsePrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM data: no PEM block found")
	}

	// 1. Try SEC1 format (-----BEGIN EC PRIVATE KEY-----)
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// 2. Try PKCS#8 format (-----BEGIN PRIVATE KEY-----)
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey); ok {
			return ecKey, nil
		}
		return nil, fmt.Errorf("PKCS#8 key contains %T, expected *ecdsa.PrivateKey", pkcs8Key)
	}

	return nil, fmt.Errorf("failed to parse ECDSA private key (not SEC1 or PKCS#8): %w", err)
}
