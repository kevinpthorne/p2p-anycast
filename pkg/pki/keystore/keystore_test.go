package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
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
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("identity.key file was not created on disk")
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
}
