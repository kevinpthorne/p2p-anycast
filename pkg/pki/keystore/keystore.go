package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
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

	// EncryptedKeyPEMType is the PEM header type for AES-256-GCM encrypted node identity keys.
	EncryptedKeyPEMType = "ENCRYPTED ANYCAST KEY"

	pbkdf2Iterations = 210000
	pbkdf2SaltSize   = 16
	gcmNonceSize     = 12
	aesKeySize       = 32
	envelopeVersion  = 0x01
)

var (
	ErrPassphraseRequired = errors.New("encrypted key requires a passphrase (set Options.Passphrase, ANYCAST_KEY_PASSPHRASE, or systemd key.passphrase credential)")
	ErrDecryptionFailed   = errors.New("failed to decrypt key: invalid passphrase or corrupted ciphertext")
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
	Passphrase  string       // Optional passphrase for AES-256-GCM encryption at rest
}

// resolvePassphrase resolves the key encryption passphrase from explicit Options,
// environment variable ANYCAST_KEY_PASSPHRASE, or systemd $CREDENTIALS_DIRECTORY/key.passphrase.
func resolvePassphrase(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("ANYCAST_KEY_PASSPHRASE"); env != "" {
		return env
	}
	if credDir := os.Getenv("CREDENTIALS_DIRECTORY"); credDir != "" {
		if data, err := os.ReadFile(filepath.Join(credDir, "key.passphrase")); err == nil {
			return strings.TrimRight(string(data), "\r\n")
		}
	}
	return ""
}

// DeriveKeyPBKDF2 derives a keyLen-byte key from a passphrase and salt using PBKDF2-HMAC-SHA256 (RFC 8018).
func DeriveKeyPBKDF2(passphrase, salt []byte, iterations, keyLen int) []byte {
	prf := func(key, data []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return mac.Sum(nil)
	}
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte
	var blockBuf [4]byte

	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(blockBuf[:], uint32(block))
		in := make([]byte, len(salt)+4)
		copy(in, salt)
		copy(in[len(salt):], blockBuf[:])

		u := prf(passphrase, in)
		t := make([]byte, len(u))
		copy(t, u)

		for i := 2; i <= iterations; i++ {
			u = prf(passphrase, u)
			subtle.XORBytes(t, t, u)
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// EncryptBytesWithPassphrase encrypts arbitrary key material with PBKDF2-HMAC-SHA256 + AES-256-GCM
// and encodes the envelope as a PEM block with the specified pemType.
func EncryptBytesWithPassphrase(plaintext []byte, passphrase string, pemType string) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("cannot encrypt empty key material")
	}
	if passphrase == "" {
		return nil, ErrPassphraseRequired
	}

	salt := make([]byte, pbkdf2SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generating PBKDF2 salt: %w", err)
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating AES-GCM nonce: %w", err)
	}

	kek := DeriveKeyPBKDF2([]byte(passphrase), salt, pbkdf2Iterations, aesKeySize)
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("initializing AES-256 cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initializing AES-256-GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(pemType))

	envelope := make([]byte, 1+pbkdf2SaltSize+gcmNonceSize+len(ciphertext))
	envelope[0] = envelopeVersion
	copy(envelope[1:1+pbkdf2SaltSize], salt)
	copy(envelope[1+pbkdf2SaltSize:1+pbkdf2SaltSize+gcmNonceSize], nonce)
	copy(envelope[1+pbkdf2SaltSize+gcmNonceSize:], ciphertext)

	pemBlock := &pem.Block{
		Type: pemType,
		Headers: map[string]string{
			"KDF":    "PBKDF2-HMAC-SHA256",
			"Cipher": "AES-256-GCM",
		},
		Bytes: envelope,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

// DecryptBytesWithPassphrase decodes a PEM block of expectedPEMType and decrypts its AES-256-GCM payload.
func DecryptBytesWithPassphrase(pemData []byte, passphrase string, expectedPEMType string) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != expectedPEMType {
		return nil, fmt.Errorf("invalid PEM block: expected %q", expectedPEMType)
	}
	if passphrase == "" {
		return nil, ErrPassphraseRequired
	}

	minLen := 1 + pbkdf2SaltSize + gcmNonceSize + 16
	if len(block.Bytes) < minLen {
		return nil, ErrDecryptionFailed
	}
	if block.Bytes[0] != envelopeVersion {
		return nil, fmt.Errorf("unsupported encrypted key envelope version: 0x%02x", block.Bytes[0])
	}

	salt := block.Bytes[1 : 1+pbkdf2SaltSize]
	nonce := block.Bytes[1+pbkdf2SaltSize : 1+pbkdf2SaltSize+gcmNonceSize]
	ciphertext := block.Bytes[1+pbkdf2SaltSize+gcmNonceSize:]

	kek := DeriveKeyPBKDF2([]byte(passphrase), salt, pbkdf2Iterations, aesKeySize)
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()

	aesBlock, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("initializing AES-256 cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, fmt.Errorf("initializing AES-256-GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(expectedPEMType))
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// EncryptKeyData encrypts raw identity key bytes using PBKDF2-HMAC-SHA256 and AES-256-GCM.
func EncryptKeyData(plaintext []byte, passphrase string) ([]byte, error) {
	return EncryptBytesWithPassphrase(plaintext, passphrase, EncryptedKeyPEMType)
}

// DecryptKeyData decrypts an ENCRYPTED ANYCAST KEY PEM block using the provided passphrase.
func DecryptKeyData(pemData []byte, passphrase string) ([]byte, error) {
	return DecryptBytesWithPassphrase(pemData, passphrase, EncryptedKeyPEMType)
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
	passphrase := resolvePassphrase(opts.Passphrase)

	// If an inline key is provided directly in KeyFilePath, load it immediately as Filesystem tier.
	if opts.KeyFilePath != "" && isInlineKey(opts.KeyFilePath) {
		log.Printf("[Keystore] WARNING: Using inline filesystem-tier identity key; hardware keystore (TPM 2.0 / Secure Enclave) is recommended for production")
		priv, err := tryFilesystem(opts.KeyFilePath, false, passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to load inline identity key: %w", err)
		}
		return buildIdentity(priv, TierFilesystem)
	}

	// If TierFilesystem is explicitly forced, bypass hardware tiers and go straight to filesystem.
	if opts.ForceTier == TierFilesystem {
		log.Printf("[Keystore] WARNING: TierFilesystem explicitly forced; bypassing hardware keystore (TPM 2.0 / Secure Enclave)")
		keyPath := opts.KeyFilePath
		if keyPath == "" {
			keyPath = "identity.key"
		}
		priv, err := tryFilesystem(keyPath, opts.AllowCreate, passphrase)
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
	log.Printf("[Keystore] WARNING: Hardware keystore (TPM 2.0 / Secure Enclave) unavailable; falling back to filesystem-based identity key")

	// Check ANYCAST_IDENTITY_KEY env var if set
	if envKey := strings.TrimSpace(os.Getenv("ANYCAST_IDENTITY_KEY")); envKey != "" {
		priv, err := tryFilesystem(envKey, opts.AllowCreate, passphrase)
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
	priv, err := tryFilesystem(keyPath, opts.AllowCreate, passphrase)
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
// GenerateTestECDSAIdentity generates an ephemeral in-memory ECDSA P-256 identity key for unit tests,
// mirroring hardware TPM2 and Apple Secure Enclave identities (multihash SHA2-256 peer IDs).
func GenerateTestECDSAIdentity() (*IdentityKey, error) {
	priv, _, err := ic.GenerateKeyPair(ic.ECDSA, 256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate test ECDSA identity key: %w", err)
	}
	return buildIdentity(priv, TierFilesystem)
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

// tryTPM2 probes a TPM 2.0 device (/dev/tpmrm0 or /dev/tpm0) and deterministically derives
// a hardware-anchored P-256 identity key from the TPM Owner Hierarchy primary seed using
// CreatePrimary + ECDHZGen.
func tryTPM2() (*ecdsa.PrivateKey, error) {
	devices := []string{"/dev/tpmrm0", "/dev/tpm0"}
	var lastErr error
	for _, dev := range devices {
		rwc, err := tpm2.OpenTPM(dev)
		if err != nil {
			lastErr = err
			continue
		}
		key, kErr := deriveIdentityFromTPM(rwc)
		_ = rwc.Close()
		if kErr == nil && key != nil {
			return key, nil
		}
		lastErr = kErr
	}
	if lastErr != nil {
		return nil, fmt.Errorf("no TPM 2.0 device usable: %w", lastErr)
	}
	return nil, errors.New("no TPM 2.0 device accessible")
}

// deriveIdentityFromTPM creates a deterministic ECC P-256 primary key under the TPM Owner
// hierarchy and performs an internal ECDH scalar multiplication against a fixed generator point
// to derive a deterministic P-256 identity key tied to the TPM's non-exportable primary seed.
func deriveIdentityFromTPM(rw io.ReadWriter) (*ecdsa.PrivateKey, error) {
	uniqueSeed := sha256.Sum256([]byte("p2p-anycast:tpm2:primary-template:v1"))
	primaryTemplate := tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: uniqueSeed[:],
				YRaw: uniqueSeed[:],
			},
		},
	}

	handle, _, err := tpm2.CreatePrimary(rw, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", primaryTemplate)
	if err != nil {
		return nil, fmt.Errorf("TPM2_CreatePrimary failed: %w", err)
	}
	defer func() {
		_ = tpm2.FlushContext(rw, handle)
	}()

	curve := elliptic.P256()
	gx, gy := curve.ScalarBaseMult([]byte{0x02})
	zPoint, err := tpm2.ECDHZGen(rw, handle, "", tpm2.ECPoint{
		XRaw: gx.Bytes(),
		YRaw: gy.Bytes(),
	})
	if err != nil {
		return nil, fmt.Errorf("TPM2_ECDH_ZGen failed: %w", err)
	}

	mac := hmac.New(sha256.New, []byte("p2p-anycast:tpm2:identity:v1"))
	mac.Write(zPoint.XRaw)
	mac.Write(zPoint.YRaw)
	digest := mac.Sum(nil)

	order := curve.Params().N
	one := big.NewInt(1)
	d := new(big.Int).SetBytes(digest)
	d.Mod(d, new(big.Int).Sub(order, one))
	d.Add(d, one)

	pubX, pubY := curve.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     pubX,
			Y:     pubY,
		},
		D: d,
	}, nil
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
// 0. Encrypted PEM format (-----BEGIN ENCRYPTED ANYCAST KEY-----)
// 1. libp2p protobuf format (libp2p default)
// 2. Base64-encoded libp2p protobuf format
// 3. SEC1 or PKCS#8 PEM format (backwards compatibility)
func parsePrivateKey(data []byte, passphrase string) (ic.PrivKey, error) {
	trimmedStr := strings.TrimSpace(string(data))

	// 0. Check for AES-256-GCM encrypted key at rest
	if strings.Contains(trimmedStr, "-----BEGIN "+EncryptedKeyPEMType+"-----") {
		decrypted, err := DecryptKeyData(data, passphrase)
		if err != nil {
			return nil, err
		}
		defer func() {
			for i := range decrypted {
				decrypted[i] = 0
			}
		}()
		return parseUnencryptedPrivateKey(decrypted)
	}

	log.Printf("[Keystore] WARNING: Identity key is stored unencrypted on filesystem; set ANYCAST_KEY_PASSPHRASE or Options.Passphrase to enable AES-256-GCM encryption at rest")
	return parseUnencryptedPrivateKey(data)
}

func parseUnencryptedPrivateKey(data []byte) (ic.PrivKey, error) {
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

	return nil, errors.New("unrecognized identity key format (expected encrypted PEM, libp2p protobuf, base64, or ECDSA PEM)")
}

// tryFilesystem loads an existing key (from file or inline string), or generates a new
// libp2p Ed25519 key if allowed.
func tryFilesystem(pathOrData string, allowCreate bool, passphrase string) (ic.PrivKey, error) {
	trimmed := strings.TrimSpace(pathOrData)
	if trimmed == "" {
		return nil, errors.New("empty identity key path or data")
	}

	// 1. Check if the string itself is inline key data
	if isInlineKey(trimmed) {
		return parsePrivateKey([]byte(trimmed), passphrase)
	}

	// 2. Read from filesystem path
	data, err := os.ReadFile(trimmed)
	if err == nil {
		return parsePrivateKey(data, passphrase)
	}

	// If read failed, check if systemd passed the file via LoadCredential ($CREDENTIALS_DIRECTORY)
	if credDir := os.Getenv("CREDENTIALS_DIRECTORY"); credDir != "" {
		candidates := []string{
			filepath.Join(credDir, filepath.Base(trimmed)),
			filepath.Join(credDir, "identity.key"),
		}
		for _, c := range candidates {
			if credData, cErr := os.ReadFile(c); cErr == nil {
				return parsePrivateKey(credData, passphrase)
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

	// 3. Generate and save new key using libp2p default (Ed25519)
	priv, _, err := ic.GenerateKeyPair(ic.Ed25519, 0)
	if err != nil {
		return nil, fmt.Errorf("generating libp2p Ed25519 key: %w", err)
	}

	keyBytes, err := ic.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshaling libp2p private key: %w", err)
	}

	outBytes := keyBytes
	if passphrase != "" {
		encrypted, encErr := EncryptKeyData(keyBytes, passphrase)
		if encErr != nil {
			return nil, fmt.Errorf("encrypting identity key at rest: %w", encErr)
		}
		outBytes = encrypted
	} else {
		log.Printf("[Keystore] WARNING: Generating unencrypted identity key on disk at %q; set ANYCAST_KEY_PASSPHRASE or Options.Passphrase for AES-256-GCM encryption at rest", trimmed)
	}

	if dir := filepath.Dir(trimmed); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("creating directory %q: %w", dir, err)
		}
	}

	if err := os.WriteFile(trimmed, outBytes, 0600); err != nil {
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

