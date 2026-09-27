package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
)

func TestKeystoreNoRAMFallback(t *testing.T) {
	// Attempting to load a nonexistent key without AllowCreate MUST fail loudly
	opts := Options{
		KeyFilePath: "/nonexistent/path/to/identity.key",
		AllowCreate: false,
	}

	idKey, err := LoadOrGenerateIdentity(opts)
	if err == nil {
		t.Fatalf("expected error loading nonexistent key without AllowCreate, got identity tier: %v", idKey.Tier())
	}
}

func TestKeystoreFilesystem(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keystore-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "test_identity.key")

	opts := Options{
		KeyFilePath: keyPath,
		AllowCreate: true,
		ForceTier:   TierFilesystem,
	}

	idKey1, err := LoadOrGenerateIdentity(opts)
	if err != nil {
		t.Fatalf("failed to generate filesystem key: %v", err)
	}

	if idKey1.Tier() != TierFilesystem {
		t.Fatalf("expected tier %s, got %s", TierFilesystem, idKey1.Tier())
	}

	// Verify file was written
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("identity.key file was not created on disk: %v", err)
	}

	// Verify it is NOT a PEM file by default
	if strings.Contains(string(data), "-----BEGIN") {
		t.Fatal("identity.key should not be PEM formatted by default")
	}

	// Verify it parses as a libp2p default protobuf key
	unmarshaled, err := ic.UnmarshalPrivateKey(data)
	if err != nil {
		t.Fatalf("failed to unmarshal libp2p protobuf private key from disk: %v", err)
	}
	if unmarshaled.Type() != pb.KeyType_Ed25519 {
		t.Fatalf("expected Ed25519 key by default, got %v", unmarshaled.Type())
	}

	// Load existing file without allowCreate
	optsLoad := Options{
		KeyFilePath: keyPath,
		AllowCreate: false,
		ForceTier:   TierFilesystem,
	}

	idKey2, err := LoadOrGenerateIdentity(optsLoad)
	if err != nil {
		t.Fatalf("failed to reload existing filesystem key: %v", err)
	}

	if idKey2.Tier() != TierFilesystem {
		t.Fatalf("expected tier %s, got %s", TierFilesystem, idKey2.Tier())
	}

	// Peer ID must be stable across reloads of the same key
	if idKey1.PeerID() != idKey2.PeerID() {
		t.Fatalf("Peer ID changed across reloads: %s != %s", idKey1.PeerID(), idKey2.PeerID())
	}
}

func TestKeystoreLibp2pBase64(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keystore-b64-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	priv, _, err := ic.GenerateKeyPair(ic.Ed25519, 0)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	keyBytes, err := ic.MarshalPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	b64Str := base64.StdEncoding.EncodeToString(keyBytes)

	// 1. File containing base64 string
	keyPath := filepath.Join(tempDir, "base64_identity.key")
	if err := os.WriteFile(keyPath, []byte(b64Str), 0600); err != nil {
		t.Fatalf("failed to write base64 key file: %v", err)
	}

	idKey, err := LoadOrGenerateIdentity(Options{
		KeyFilePath: keyPath,
		AllowCreate: false,
	})
	if err != nil {
		t.Fatalf("failed to load base64 key from file: %v", err)
	}
	if idKey.Libp2pPrivKey().Type() != pb.KeyType_Ed25519 {
		t.Fatalf("expected Ed25519, got %v", idKey.Libp2pPrivKey().Type())
	}

	// 2. Inline base64 string
	inlineKey, err := LoadOrGenerateIdentity(Options{
		KeyFilePath: b64Str,
	})
	if err != nil {
		t.Fatalf("failed to load inline base64 key: %v", err)
	}
	if inlineKey.PeerID() != idKey.PeerID() {
		t.Fatalf("mismatched Peer IDs between file and inline base64: %s != %s", inlineKey.PeerID(), idKey.PeerID())
	}
}

func TestKeystorePKCS8(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keystore-pkcs8-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal PKCS#8 key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	keyPath := filepath.Join(tempDir, "pkcs8_identity.key")
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	idKey, err := LoadOrGenerateIdentity(Options{
		KeyFilePath: keyPath,
		AllowCreate: false,
	})
	if err != nil {
		t.Fatalf("failed to load PKCS#8 key: %v", err)
	}

	if idKey.Tier() != TierFilesystem {
		t.Fatalf("expected tier %s, got %s", TierFilesystem, idKey.Tier())
	}

	if idKey.PeerID() == "" {
		t.Fatal("empty Peer ID from PKCS#8 key")
	}
}

func TestKeystoreInlinePEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}

	pemString := string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}))

	idKey, err := LoadOrGenerateIdentity(Options{
		KeyFilePath: pemString,
	})
	if err != nil {
		t.Fatalf("failed to load inline PEM key: %v", err)
	}

	if idKey.Tier() != TierFilesystem {
		t.Fatalf("expected tier %s, got %s", TierFilesystem, idKey.Tier())
	}

	if idKey.PeerID() == "" {
		t.Fatal("empty Peer ID from inline PEM key")
	}
}

func TestKeystoreMissingDirCreation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keystore-dir-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Nested subdirectories that do not exist yet
	keyPath := filepath.Join(tempDir, "nested", "sub", "dir", "identity.key")

	idKey, err := LoadOrGenerateIdentity(Options{
		KeyFilePath: keyPath,
		AllowCreate: true,
	})
	if err != nil {
		t.Fatalf("failed to generate key in nested path: %v", err)
	}

	if idKey.PeerID() == "" {
		t.Fatal("empty Peer ID")
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatalf("file %s was not created", keyPath)
	}
}

func TestGenerateTestIdentity(t *testing.T) {
	idKey, err := GenerateTestIdentity()
	if err != nil {
		t.Fatalf("failed to generate test identity: %v", err)
	}
	if idKey.Tier() != TierFilesystem {
		t.Fatalf("expected tier %s, got %s", TierFilesystem, idKey.Tier())
	}
	if idKey.PeerID() == "" {
		t.Fatal("empty Peer ID")
	}
	if idKey.Libp2pPrivKey().Type() != pb.KeyType_Ed25519 {
		t.Fatalf("expected Ed25519, got %v", idKey.Libp2pPrivKey().Type())
	}
}

func TestKeystoreCredentialsDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keystore-cred-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	credDir := filepath.Join(tempDir, "creds")
	if err := os.MkdirAll(credDir, 0700); err != nil {
		t.Fatalf("failed to create cred dir: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	keyBytes, _ := x509.MarshalECPrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	credKeyPath := filepath.Join(credDir, "identity.key")
	if err := os.WriteFile(credKeyPath, pemBytes, 0600); err != nil {
		t.Fatalf("failed to write cred key: %v", err)
	}

	t.Setenv("CREDENTIALS_DIRECTORY", credDir)

	// Even when pointing to an unreadable or non-existent path, it loads from CREDENTIALS_DIRECTORY
	idKey, err := LoadOrGenerateIdentity(Options{
		KeyFilePath: "/var/keys/identity.key",
		AllowCreate: false,
	})
	if err != nil {
		t.Fatalf("failed to load identity key via CREDENTIALS_DIRECTORY: %v", err)
	}

	if idKey.PeerID() == "" {
		t.Fatal("empty Peer ID from credentials directory key")
	}
}

func TestKeystoreHardwareOnlyGenerateWhenHardwareFails(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keystore-wf-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "waterfall_identity.key")

	// When TPM is forced and unavailable, it should fail without creating keyPath
	_, err = LoadOrGenerateIdentity(Options{
		KeyFilePath: keyPath,
		AllowCreate: true,
		ForceTier:   TierTPM2,
	})
	if err == nil {
		t.Fatal("expected error when forcing unavailable TPM")
	}

	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("file should NOT be generated when hardware tier is forced")
	}

	// When Secure Enclave is forced and unavailable, it should fail without creating keyPath
	_, err = LoadOrGenerateIdentity(Options{
		KeyFilePath: keyPath,
		AllowCreate: true,
		ForceTier:   TierSecureEnclave,
	})
	if err == nil {
		t.Fatal("expected error when forcing unavailable Secure Enclave")
	}

	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("file should NOT be generated when hardware tier is forced")
	}
}
