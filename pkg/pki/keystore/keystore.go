package keystore

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
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
// The anchor (TPM/SE hardware key or filesystem libp2p key) is the authoritative persistent identity.
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
	KeyFilePath string       // File path or inline private key string (protobuf base64 or PEM)
	AllowCreate bool         // If true and KeyFilePath does not exist, generate and write a new key
	ForceTier   KeystoreTier // If set, only attempt this tier (useful for testing)
}

// LoadOrGenerateIdentity loads or generates a node identity following the anchor waterfall:
// Tier 1A (TPM 2.0) -> Tier 1B (Apple Secure Enclave) -> Tier 2 (Filesystem).
//
// Hardware anchors (TPM / SE) are always probed first. The filesystem key file is only
// loaded or generated if hardware anchors are unavailable or fail.
//
// If ForceTier is specified, only that specific tier is attempted.
// If KeyFilePath contains inline key data, it loads directly from the inline data.
func LoadOrGenerateIdentity(opts Options) (*IdentityKey, error) {
	// If an inline key is provided directly in KeyFilePath, load it immediately as Filesystem tier.
	if opts.KeyFilePath != "" && isInlineKey(opts.KeyFilePath) {
		priv, err := tryFilesystem(opts.KeyFilePath, false)
		if err != nil {
			return nil, fmt.Errorf("failed to load inline identity key: %w", err)
		}
		return buildIdentity(priv, TierFilesystem)
	}

	// If TierFilesystem is explicitly forced, bypass hardware tiers and go straight to filesystem.
	if opts.ForceTier == TierFilesystem {
		keyPath := opts.KeyFilePath
		if keyPath == "" {
			keyPath = "identity.key"
		}
		priv, err := tryFilesystem(keyPath, opts.AllowCreate)
		if err != nil {
			return nil, fmt.Errorf("failed to load identity key (%s): %w", keyPath, err)
		}
		return buildIdentity(priv, TierFilesystem)
	}

	// 1. Tier 1A: TPM 2.0
	if opts.ForceTier == "" || opts.ForceTier == TierTPM2 {
		if tpmKey, err := tryTPM2(); err == nil && tpmKey != nil {
			return buildIdentityFromECDSA(tpmKey, TierTPM2)
		} else if opts.ForceTier == TierTPM2 {
			return nil, fmt.Errorf("TPM 2.0 forced but unavailable: %w", err)
		}
	}

	// 2. Tier 1B: Apple Secure Enclave
	if opts.ForceTier == "" || opts.ForceTier == TierSecureEnclave {
		if seKey, err := trySecureEnclave(); err == nil && seKey != nil {
			return buildIdentityFromECDSA(seKey, TierSecureEnclave)
		} else if opts.ForceTier == TierSecureEnclave {
			return nil, fmt.Errorf("Secure Enclave forced but unavailable: %w", err)
		}
	}

	// 3. Tier 2: Filesystem fallback (only reached if TPM and SE failed or are unavailable)
	// Check ANYCAST_IDENTITY_KEY env var if set
	if envKey := strings.TrimSpace(os.Getenv("ANYCAST_IDENTITY_KEY")); envKey != "" {
		priv, err := tryFilesystem(envKey, opts.AllowCreate)
		if err != nil {
			return nil, fmt.Errorf("failed to load identity key from ANYCAST_IDENTITY_KEY: %w", err)
		}
		return buildIdentity(priv, TierFilesystem)
	}

	// Default to KeyFilePath (or "identity.key" in current working directory)
	keyPath := opts.KeyFilePath
	if keyPath == "" {
		keyPath = "identity.key"
	}
	priv, err := tryFilesystem(keyPath, opts.AllowCreate)
	if err != nil {
		return nil, fmt.Errorf("no persistent identity key found (TPM/SE unavailable, and %s could not be loaded): %w", keyPath, err)
	}
	return buildIdentity(priv, TierFilesystem)
}

// GenerateTestIdentity generates an ephemeral in-memory Ed25519 identity key for unit tests.
// This is strictly for automated tests and avoids touching the filesystem.
func GenerateTestIdentity() (*IdentityKey, error) {
	priv, _, err := ic.GenerateKeyPair(ic.Ed25519, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to generate test identity key: %w", err)
	}
	return buildIdentity(priv, TierFilesystem)
}

// NewEphemeralIdentity is an alias for GenerateTestIdentity for testing purposes.
func NewEphemeralIdentity() (*IdentityKey, error) {
	return GenerateTestIdentity()
}

// buildIdentity wraps a libp2p private key and derives the stable Peer ID.
func buildIdentity(priv ic.PrivKey, tier KeystoreTier) (*IdentityKey, error) {
	pID, err := peer.IDFromPublicKey(priv.GetPublic())
	if err != nil {
		return nil, fmt.Errorf("failed to derive Peer ID from public key: %w", err)
	}

	return &IdentityKey{
		tier:       tier,
		libp2pPriv: priv,
		peerID:     pID,
	}, nil
}

// buildIdentityFromECDSA wraps an ECDSA key (e.g. from TPM or Apple Secure Enclave) as a libp2p identity.
func buildIdentityFromECDSA(key *ecdsa.PrivateKey, tier KeystoreTier) (*IdentityKey, error) {
	p2pPriv, _, err := ic.ECDSAKeyPairFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap anchor key as libp2p identity: %w", err)
	}
	return buildIdentity(p2pPriv, tier)
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

// isInlineKey checks whether a string contains inline key data rather than a file path.
func isInlineKey(s string) bool {
	trimmed := strings.TrimSpace(s)
	if strings.Contains(trimmed, "-----BEGIN") {
		return true
	}
	if b64, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(b64) > 0 {
		if _, err := ic.UnmarshalPrivateKey(b64); err == nil {
			return true
		}
	}
	return false
}

// parsePrivateKey parses key bytes supporting:
// 1. libp2p protobuf format (libp2p default)
// 2. Base64-encoded libp2p protobuf format
// 3. SEC1 or PKCS#8 PEM format (backwards compatibility)
func parsePrivateKey(data []byte) (ic.PrivKey, error) {
	// 1. Try standard libp2p protobuf binary format
	if priv, err := ic.UnmarshalPrivateKey(data); err == nil {
		return priv, nil
	}

	// 2. Try base64-encoded protobuf string
	trimmedStr := strings.TrimSpace(string(data))
	if b64, err := base64.StdEncoding.DecodeString(trimmedStr); err == nil && len(b64) > 0 {
		if priv, err := ic.UnmarshalPrivateKey(b64); err == nil {
			return priv, nil
		}
	}

	// 3. Try PEM format (SEC1 or PKCS#8) for backwards compatibility
	if strings.Contains(trimmedStr, "-----BEGIN") {
		ecKey, err := parsePrivateKeyPEM(data)
		if err != nil {
			return nil, err
		}
		p2pPriv, _, err := ic.ECDSAKeyPairFromKey(ecKey)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap legacy ECDSA key: %w", err)
		}
		return p2pPriv, nil
	}

	return nil, errors.New("unrecognized identity key format (expected libp2p protobuf, base64, or PEM)")
}

// tryFilesystem loads an existing key (from file or inline string), or generates a new
// libp2p Ed25519 key if allowed.
func tryFilesystem(pathOrData string, allowCreate bool) (ic.PrivKey, error) {
	trimmed := strings.TrimSpace(pathOrData)
	if trimmed == "" {
		return nil, errors.New("empty identity key path or data")
	}

	// 1. Check if the string itself is inline key data
	if isInlineKey(trimmed) {
		return parsePrivateKey([]byte(trimmed))
	}

	// 2. Read from filesystem path
	data, err := os.ReadFile(trimmed)
	if err == nil {
		return parsePrivateKey(data)
	}

	// If read failed, check if systemd passed the file via LoadCredential ($CREDENTIALS_DIRECTORY)
	if credDir := os.Getenv("CREDENTIALS_DIRECTORY"); credDir != "" {
		candidates := []string{
			filepath.Join(credDir, filepath.Base(trimmed)),
			filepath.Join(credDir, "identity.key"),
		}
		for _, c := range candidates {
			if credData, cErr := os.ReadFile(c); cErr == nil {
				return parsePrivateKey(credData)
			}
		}
	}

	// File read failed. Only attempt creation if allowCreate is true and file does not exist.
	if !allowCreate || !errors.Is(err, os.ErrNotExist) {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("reading key file %q: %w (hint: file or directory is owned by root; set dynamicUser = false or use systemd LoadCredential)", trimmed, err)
		}
		return nil, fmt.Errorf("reading key file %q: %w", trimmed, err)
	}

	// 3. Generate and save new key using libp2p default (Ed25519) and libp2p standard protobuf wire format
	priv, _, err := ic.GenerateKeyPair(ic.Ed25519, 0)
	if err != nil {
		return nil, fmt.Errorf("generating libp2p Ed25519 key: %w", err)
	}

	keyBytes, err := ic.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshaling libp2p private key: %w", err)
	}

	if dir := filepath.Dir(trimmed); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("creating directory %q: %w", dir, err)
		}
	}

	if err := os.WriteFile(trimmed, keyBytes, 0600); err != nil {
		return nil, fmt.Errorf("writing key file %q: %w", trimmed, err)
	}

	return priv, nil
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
