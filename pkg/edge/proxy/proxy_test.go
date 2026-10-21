package proxy

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type testKeyPair struct {
	priv   ic.PrivKey
	peerID peer.ID
}

func generateTestEd25519Key(t *testing.T) (*testKeyPair, error) {
	t.Helper()
	priv, pub, err := ic.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}
	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return &testKeyPair{priv: priv, peerID: pid}, nil
}

func TestPROXYv2HeaderEncodeDecodeIPv4(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("203.0.113.195"), Port: 54321}
	dst := &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}

	header, err := BuildPROXYv2Header(src, dst)
	if err != nil {
		t.Fatalf("failed to build PROXYv2 header: %v", err)
	}

	buf := bytes.NewReader(header)
	parsedSrc, parsedDst, err := ParsePROXYv2Header(buf)
	if err != nil {
		t.Fatalf("failed to parse PROXYv2 header: %v", err)
	}

	if !parsedSrc.IP.Equal(src.IP) || parsedSrc.Port != src.Port {
		t.Fatalf("src mismatch: expected %v, got %v", src, parsedSrc)
	}
	if !parsedDst.IP.Equal(dst.IP) || parsedDst.Port != dst.Port {
		t.Fatalf("dst mismatch: expected %v, got %v", dst, parsedDst)
	}
}

func TestPROXYv2HeaderEncodeDecodeIPv6(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 49152}
	dst := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 80}

	header, err := BuildPROXYv2Header(src, dst)
	if err != nil {
		t.Fatalf("failed to build PROXYv2 header IPv6: %v", err)
	}

	buf := bytes.NewReader(header)
	parsedSrc, parsedDst, err := ParsePROXYv2Header(buf)
	if err != nil {
		t.Fatalf("failed to parse PROXYv2 header IPv6: %v", err)
	}

	if !parsedSrc.IP.Equal(src.IP) || parsedSrc.Port != src.Port {
		t.Fatalf("src mismatch: expected %v, got %v", src, parsedSrc)
	}
	if !parsedDst.IP.Equal(dst.IP) || parsedDst.Port != dst.Port {
		t.Fatalf("dst mismatch: expected %v, got %v", dst, parsedDst)
	}
}

func TestSignedPROXYv2HeaderSignAndVerify(t *testing.T) {
	edgeKey, err := generateTestEd25519Key(t)
	if err != nil {
		t.Fatalf("failed to generate edge key: %v", err)
	}
	otherKey, err := generateTestEd25519Key(t)
	if err != nil {
		t.Fatalf("failed to generate other key: %v", err)
	}

	src := &net.TCPAddr{IP: net.ParseIP("198.51.100.42"), Port: 61234}
	dst := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 443}
	var bindingID [16]byte
	copy(bindingID[:], "proxy-binding-01")

	signedHdr, err := BuildSignedPROXYv2Header(src, dst, bindingID, edgeKey.priv)
	if err != nil {
		t.Fatalf("BuildSignedPROXYv2Header failed: %v", err)
	}

	// 1. VerifySignedPROXYv2Header with matching Edge PubKey and bindingID must succeed
	vSrc, vDst, err := VerifySignedPROXYv2Header(bytes.NewReader(signedHdr), bindingID, edgeKey.priv.GetPublic())
	if err != nil {
		t.Fatalf("VerifySignedPROXYv2Header failed: %v", err)
	}
	if !vSrc.IP.Equal(src.IP) || vSrc.Port != src.Port {
		t.Fatalf("verified src mismatch: %v vs %v", vSrc, src)
	}
	if !vDst.IP.Equal(dst.IP) || vDst.Port != dst.Port {
		t.Fatalf("verified dst mismatch: %v vs %v", vDst, dst)
	}

	// 2. VerifySignedPROXYv2Header with wrong Edge PubKey must fail
	if _, _, err := VerifySignedPROXYv2Header(bytes.NewReader(signedHdr), bindingID, otherKey.priv.GetPublic()); err == nil {
		t.Fatal("expected VerifySignedPROXYv2Header to fail with wrong expected Edge PubKey")
	}

	// 3. Tampering with client source IP in the address block must invalidate TLV signature
	tampered := make([]byte, len(signedHdr))
	copy(tampered, signedHdr)
	tampered[16] ^= 0xFF // flip first byte of IPv4 source address
	if _, _, err := VerifySignedPROXYv2Header(bytes.NewReader(tampered), bindingID, edgeKey.priv.GetPublic()); err == nil {
		t.Fatal("expected VerifySignedPROXYv2Header to fail when source IP is tampered")
	}

	// 4. Standard ParsePROXYv2Header must still remain backward-compatible and skip TLVs cleanly
	pSrc, pDst, err := ParsePROXYv2Header(bytes.NewReader(signedHdr))
	if err != nil {
		t.Fatalf("ParsePROXYv2Header failed on signed header: %v", err)
	}
	if !pSrc.IP.Equal(src.IP) || !pDst.IP.Equal(dst.IP) {
		t.Fatal("ParsePROXYv2Header IP mismatch on signed header")
	}
}
