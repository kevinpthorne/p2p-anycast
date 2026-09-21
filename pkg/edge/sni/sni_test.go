package sni

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

func TestExtractSNIValidClientHello(t *testing.T) {
	// Create mock TLS client handshake to capture bytes
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	expectedSNI := "secure.meshcast.network"
	var capturedSNI string
	var extractErr error
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			extractErr = err
			return
		}
		capturedSNI, extractErr = ExtractSNI(buf[:n])
	}()

	// Connect TLS client with ServerName
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	rawConn, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer rawConn.Close()

	tlsConfig := &tls.Config{
		ServerName:         expectedSNI,
		InsecureSkipVerify: true,
	}
	tlsClient := tls.Client(rawConn, tlsConfig)
	_ = tlsClient.Handshake() // Will fail handshake after ClientHello since server didn't respond, which is fine

	wg.Wait()

	if extractErr != nil {
		t.Fatalf("ExtractSNI error: %v", err)
	}
	if capturedSNI != expectedSNI {
		t.Fatalf("expected SNI %q, got %q", expectedSNI, capturedSNI)
	}
}

func TestExtractSNIMalformedData(t *testing.T) {
	// 1. Non-TLS data (e.g. HTTP GET)
	httpData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_, err := ExtractSNI(httpData)
	if err == nil {
		t.Fatal("expected error for non-TLS data, got nil")
	}

	// 2. Truncated TLS header
	_, err = ExtractSNI([]byte{0x16, 0x03, 0x03})
	if err != ErrTruncatedRecord {
		t.Fatalf("expected ErrTruncatedRecord, got %v", err)
	}

	// 3. TLS Alert record instead of Handshake
	_, err = ExtractSNI([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x30})
	if err != ErrNotTLSHandshake {
		t.Fatalf("expected ErrNotTLSHandshake, got %v", err)
	}
}

// Generate self-signed TLS cert for testing
func GenerateTestTLSCert(t *testing.T, hostnames ...string) tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"MeshCast Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              hostnames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
}
