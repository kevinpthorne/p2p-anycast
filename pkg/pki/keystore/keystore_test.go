package keystore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeystoreRAMFallback(t *testing.T) {
	opts := Options{
		ForceTier: TierRAM,
	}

	idKey, err := LoadOrGenerateIdentity(opts)
	if err != nil {
		t.Fatalf("failed to load identity from RAM: %v", err)
	}

	if idKey.Tier() != TierRAM {
		t.Fatalf("expected tier %s, got %s", TierRAM, idKey.Tier())
	}

	if idKey.PeerID() == "" {
		t.Fatal("empty libp2p Peer ID")
	}

	if idKey.Libp2pPrivKey() == nil {
		t.Fatal("nil libp2p private key")
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

	// Peer ID must be stable across loads of the same key
	if idKey1.PeerID() != idKey2.PeerID() {
		t.Fatalf("Peer ID changed across reloads: %s != %s", idKey1.PeerID(), idKey2.PeerID())
	}
}
