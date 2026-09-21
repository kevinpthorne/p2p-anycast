package test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	"p2p-anycast/pkg/pki/keystore"
	"p2p-anycast/pkg/pki/manifest"
	"p2p-anycast/pkg/pki/mldsa"
	identity "p2p-anycast/pkg/proto/identity"
)

type TestPKI struct {
	CAPub  *mldsa87.PublicKey
	CAPriv *mldsa87.PrivateKey
}

func SetupTestPKI(t *testing.T) *TestPKI {
	pub, priv, err := mldsa.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate Root CA key: %v", err)
	}
	return &TestPKI{
		CAPub:  pub,
		CAPriv: priv,
	}
}

func (pki *TestPKI) IssueManifest(t *testing.T, subjectID string, role identity.NodeRole, idKey *keystore.IdentityKey, caps []*identity.ServiceCapability) *identity.SignedCapabilityManifest {
	now := time.Now()
	claims := &identity.IdentityClaims{
		SerialNumber:       1,
		IssuerId:           "Test Root CA",
		SubjectId:          subjectID,
		Role:               role,
		SubjectMldsaPubkey: mldsa.PublicKeyToBytes(idKey.MLDSAPubKey()),
		Libp2PPeerId:       idKey.PeerID().String(),
		NotBefore:          now.Add(-1 * time.Hour).Unix(),
		NotAfter:           now.Add(24 * time.Hour).Unix(),
		Capabilities:       caps,
	}

	signed, err := manifest.SignManifest(claims, pki.CAPriv, pki.CAPub)
	if err != nil {
		t.Fatalf("failed to sign test manifest: %v", err)
	}
	return signed
}

func StartMockTCPEchoServer(t *testing.T) (net.Listener, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock TCP echo: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return ln, ln.Addr().String()
}

func StartMockTLSEchoServer(t *testing.T, hostnames ...string) (net.Listener, string, *tls.Config) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate TLS RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"MeshCast Mock TLS"},
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

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to start TLS echo listener: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return ln, ln.Addr().String(), tlsConfig
}

func StartMockUDPEchoServer(t *testing.T) (*net.UDPConn, string) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to start mock UDP echo: %v", err)
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], clientAddr)
		}
	}()

	return conn, conn.LocalAddr().String()
}
