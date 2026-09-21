package mldsa

import (
	"bytes"
	"os"
	"testing"
)

func TestMLDSA87KeyGenAndSizes(t *testing.T) {
	pk, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pkBytes := PublicKeyToBytes(pk)
	if len(pkBytes) != PublicKeySize {
		t.Fatalf("expected public key size %d, got %d", PublicKeySize, len(pkBytes))
	}

	skBytes := PrivateKeyToBytes(sk)
	if len(skBytes) != PrivateKeySize {
		t.Fatalf("expected private key size %d, got %d", PrivateKeySize, len(skBytes))
	}

	// Round-trip unpack
	pk2, err := PublicKeyFromBytes(pkBytes)
	if err != nil {
		t.Fatalf("failed to unpack public key: %v", err)
	}
	if !bytes.Equal(PublicKeyToBytes(pk2), pkBytes) {
		t.Fatal("public keys do not match after round-trip")
	}

	sk2, err := PrivateKeyFromBytes(skBytes)
	if err != nil {
		t.Fatalf("failed to unpack private key: %v", err)
	}
	if !bytes.Equal(PrivateKeyToBytes(sk2), skBytes) {
		t.Fatal("private keys do not match after round-trip")
	}
}

func TestMLDSA87SignAndVerifyWithContext(t *testing.T) {
	pk, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	msg := []byte("Hello, post-quantum meshcast!")

	// 1. Sign with ContextCAManifest
	sig, err := Sign(sk, msg, ContextCAManifest)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("expected signature size %d, got %d", SignatureSize, len(sig))
	}

	// 2. Verify with correct context string
	if !Verify(pk, msg, ContextCAManifest, sig) {
		t.Fatal("verification failed with matching context")
	}

	// 3. Domain separation: Verify with different context string must fail
	if Verify(pk, msg, ContextNodeAuth, sig) {
		t.Fatal("verification succeeded with wrong context string (domain separation violated)")
	}

	// 4. Verification with tampered message must fail
	tamperedMsg := []byte("Hello, post-quantum meshcast?")
	if Verify(pk, tamperedMsg, ContextCAManifest, sig) {
		t.Fatal("verification succeeded with tampered message")
	}

	// 5. Verification with tampered signature must fail
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[0] ^= 0xFF
	if Verify(pk, msg, ContextCAManifest, tamperedSig) {
		t.Fatal("verification succeeded with tampered signature")
	}
}

func TestMLDSA87PEMEncodeDecode(t *testing.T) {
	pk, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	skPEM := EncodePrivateKeyToPEM(sk)
	decodedSK, err := DecodePrivateKeyFromPEM(skPEM)
	if err != nil {
		t.Fatalf("failed to decode private key PEM: %v", err)
	}
	if !bytes.Equal(PrivateKeyToBytes(decodedSK), PrivateKeyToBytes(sk)) {
		t.Fatal("private key PEM round-trip failed")
	}

	pkPEM := EncodePublicKeyToPEM(pk)
	decodedPK, err := DecodePublicKeyFromPEM(pkPEM)
	if err != nil {
		t.Fatalf("failed to decode public key PEM: %v", err)
	}
	if !bytes.Equal(PublicKeyToBytes(decodedPK), PublicKeyToBytes(pk)) {
		t.Fatal("public key PEM round-trip failed")
	}
}

func TestLoadPublicKey(t *testing.T) {
	pk, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pkPEM := string(EncodePublicKeyToPEM(pk))

	// 1. Test inline PEM string
	loaded, err := LoadPublicKey(pkPEM)
	if err != nil {
		t.Fatalf("failed to load public key from inline PEM string: %v", err)
	}
	if !bytes.Equal(PublicKeyToBytes(loaded), PublicKeyToBytes(pk)) {
		t.Fatal("loaded public key does not match original from inline PEM")
	}

	// 2. Test file path
	tmpDir := t.TempDir()
	filePath := tmpDir + "/ca.pub"
	if err := os.WriteFile(filePath, []byte(pkPEM), 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	loadedFile, err := LoadPublicKey(filePath)
	if err != nil {
		t.Fatalf("failed to load public key from file path: %v", err)
	}
	if !bytes.Equal(PublicKeyToBytes(loadedFile), PublicKeyToBytes(pk)) {
		t.Fatal("loaded public key does not match original from file")
	}

	// 3. Test ANYCAST_CA_PUB environment variable fallback
	t.Setenv("ANYCAST_CA_PUB", pkPEM)
	loadedEnv, err := LoadPublicKey("")
	if err != nil {
		t.Fatalf("failed to load public key from ANYCAST_CA_PUB env var: %v", err)
	}
	if !bytes.Equal(PublicKeyToBytes(loadedEnv), PublicKeyToBytes(pk)) {
		t.Fatal("loaded public key does not match original from ANYCAST_CA_PUB env")
	}
}

