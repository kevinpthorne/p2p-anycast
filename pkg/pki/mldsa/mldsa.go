package mldsa

import (
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

const (
	// ContextCAManifest is the FIPS 204 context string for Root CA manifest signing.
	ContextCAManifest = "p2p-anycast:ca:manifest:v1"

	// ContextNodeAuth is the FIPS 204 context string for runtime challenge-response handshakes.
	ContextNodeAuth = "p2p-anycast:node:auth:v1"

	// PublicKeySize is the size of an ML-DSA-87 public key in bytes (2592B).
	PublicKeySize = mldsa87.PublicKeySize

	// PrivateKeySize is the size of an ML-DSA-87 private key in bytes (4896B).
	PrivateKeySize = mldsa87.PrivateKeySize

	// SignatureSize is the size of an ML-DSA-87 signature in bytes (4627B).
	SignatureSize = mldsa87.SignatureSize
)

var (
	ErrInvalidPublicKeyLength  = fmt.Errorf("invalid ML-DSA-87 public key length (expected %d bytes)", PublicKeySize)
	ErrInvalidPrivateKeyLength = fmt.Errorf("invalid ML-DSA-87 private key length (expected %d bytes)", PrivateKeySize)
	ErrInvalidSignatureLength  = fmt.Errorf("invalid ML-DSA-87 signature length (expected %d bytes)", SignatureSize)
	ErrContextTooLong          = errors.New("context string exceeds 255 bytes")
	ErrDecodingPEM             = errors.New("failed to decode PEM block")
)

// GenerateKey generates a new ML-DSA-87 public/private keypair using crypto/rand.
func GenerateKey() (*mldsa87.PublicKey, *mldsa87.PrivateKey, error) {
	return mldsa87.GenerateKey(rand.Reader)
}

// Sign signs a message using the private key and an explicit context string.
func Sign(sk *mldsa87.PrivateKey, msg []byte, ctx string) ([]byte, error) {
	if sk == nil {
		return nil, errors.New("nil private key")
	}
	if len(ctx) > 255 {
		return nil, ErrContextTooLong
	}
	sig := make([]byte, SignatureSize)
	if err := mldsa87.SignTo(sk, msg, []byte(ctx), true, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// Verify verifies an ML-DSA-87 signature against the message, context string, and public key.
func Verify(pk *mldsa87.PublicKey, msg []byte, ctx string, sig []byte) bool {
	if pk == nil || len(sig) != SignatureSize {
		return false
	}
	if len(ctx) > 255 {
		return false
	}
	return mldsa87.Verify(pk, msg, []byte(ctx), sig)
}

// PublicKeyToBytes serializes the public key to a 2592-byte slice.
func PublicKeyToBytes(pk *mldsa87.PublicKey) []byte {
	if pk == nil {
		return nil
	}
	return pk.Bytes()
}

// PublicKeyFromBytes deserializes a 2592-byte slice into an ML-DSA-87 PublicKey.
func PublicKeyFromBytes(data []byte) (*mldsa87.PublicKey, error) {
	if len(data) != PublicKeySize {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidPublicKeyLength, len(data))
	}
	pk := new(mldsa87.PublicKey)
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return pk, nil
}

// PrivateKeyToBytes serializes the private key to a 4896-byte slice.
func PrivateKeyToBytes(sk *mldsa87.PrivateKey) []byte {
	if sk == nil {
		return nil
	}
	return sk.Bytes()
}

// PrivateKeyFromBytes deserializes a 4896-byte slice into an ML-DSA-87 PrivateKey.
func PrivateKeyFromBytes(data []byte) (*mldsa87.PrivateKey, error) {
	if len(data) != PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidPrivateKeyLength, len(data))
	}
	sk := new(mldsa87.PrivateKey)
	if err := sk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return sk, nil
}

// EncodePrivateKeyToPEM encodes an ML-DSA-87 private key into PEM format.
func EncodePrivateKeyToPEM(sk *mldsa87.PrivateKey) []byte {
	block := &pem.Block{
		Type:  "ML-DSA-87 PRIVATE KEY",
		Bytes: PrivateKeyToBytes(sk),
	}
	return pem.EncodeToMemory(block)
}

// DecodePrivateKeyFromPEM decodes an ML-DSA-87 private key from PEM bytes.
func DecodePrivateKeyFromPEM(pemBytes []byte) (*mldsa87.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "ML-DSA-87 PRIVATE KEY" {
		return nil, ErrDecodingPEM
	}
	return PrivateKeyFromBytes(block.Bytes)
}

// EncodePublicKeyToPEM encodes an ML-DSA-87 public key into PEM format.
func EncodePublicKeyToPEM(pk *mldsa87.PublicKey) []byte {
	block := &pem.Block{
		Type:  "ML-DSA-87 PUBLIC KEY",
		Bytes: PublicKeyToBytes(pk),
	}
	return pem.EncodeToMemory(block)
}

// DecodePublicKeyFromPEM decodes an ML-DSA-87 public key from PEM bytes.
func DecodePublicKeyFromPEM(pemBytes []byte) (*mldsa87.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "ML-DSA-87 PUBLIC KEY" {
		return nil, ErrDecodingPEM
	}
	return PublicKeyFromBytes(block.Bytes)
}

// LoadPublicKey loads an ML-DSA-87 public key from an inline PEM string,
// a file path, or the ANYCAST_CA_PUB environment variable.
func LoadPublicKey(pathOrPEM string) (*mldsa87.PublicKey, error) {
	trimmed := strings.TrimSpace(pathOrPEM)
	if strings.Contains(trimmed, "-----BEGIN") {
		return DecodePublicKeyFromPEM([]byte(trimmed))
	}

	if trimmed != "" {
		if data, err := os.ReadFile(trimmed); err == nil {
			return DecodePublicKeyFromPEM(data)
		}
	}

	// Fallback to ANYCAST_CA_PUB environment variable if set
	if env := strings.TrimSpace(os.Getenv("ANYCAST_CA_PUB")); env != "" {
		if strings.Contains(env, "-----BEGIN") {
			return DecodePublicKeyFromPEM([]byte(env))
		}
		if envData, err := os.ReadFile(env); err == nil {
			return DecodePublicKeyFromPEM(envData)
		}
	}

	if trimmed != "" {
		return nil, fmt.Errorf("failed to read public key from file %q and no valid ANYCAST_CA_PUB found", trimmed)
	}
	return nil, errors.New("no public key provided: path is empty and ANYCAST_CA_PUB is not set")
}
