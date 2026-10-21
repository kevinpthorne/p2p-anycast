package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
)

const (
	// TCPProtocolID is the libp2p protocol ID for proxied TCP streams.
	TCPProtocolID = "/p2p-anycast/tcp/1.0.0"

	// PreambleLength is 32 bytes: 16 bytes binding_id + 16 bytes hmac_token.
	PreambleLength = 32

	// TLVTypeEdgeAttestation is a custom PROXYv2 TLV type (0xE0) carrying the Edge router's
	// non-repudiation signature over (binding_id || client_addr_block).
	TLVTypeEdgeAttestation = 0xE0

	// ContextProxyV2Attestation is the domain separation context for PROXYv2 TLV signatures.
	ContextProxyV2Attestation = "p2p-anycast:proxyv2:v1"
)

var (
	// PROXYv2Signature is the 12-byte constant header for PROXY protocol v2.
	PROXYv2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

	ErrInvalidProxyHeader     = errors.New("invalid PROXYv2 header")
	ErrUnsupportedFamily      = errors.New("unsupported address family for PROXYv2")
	ErrInvalidProxySignature  = errors.New("invalid or missing Edge attestation signature in PROXYv2 TLV")
)

func buildProxyAttestationPayload(bindingID [16]byte, addrBlock []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(ContextProxyV2Attestation)
	buf.WriteByte(0)
	buf.Write(bindingID[:])
	buf.Write(addrBlock)
	return buf.Bytes()
}

// BuildPROXYv2Header creates a binary PROXYv2 header representing the client and edge endpoints.
func BuildPROXYv2Header(srcAddr, dstAddr net.Addr) ([]byte, error) {
	return BuildSignedPROXYv2Header(srcAddr, dstAddr, [16]byte{}, nil)
}

// BuildSignedPROXYv2Header creates a binary PROXYv2 header and, when edgePriv is non-nil,
// appends a custom TLV (0xE0) containing the Edge router's signature over (bindingID || addrBlock).
func BuildSignedPROXYv2Header(srcAddr, dstAddr net.Addr, bindingID [16]byte, edgePriv ic.PrivKey) ([]byte, error) {
	srcTCP, ok1 := srcAddr.(*net.TCPAddr)
	dstTCP, ok2 := dstAddr.(*net.TCPAddr)
	if !ok1 || !ok2 {
		return nil, errors.New("addresses must be *net.TCPAddr")
	}

	srcIP4 := srcTCP.IP.To4()
	dstIP4 := dstTCP.IP.To4()

	var fam byte
	var addrBlock []byte

	if srcIP4 != nil && dstIP4 != nil {
		fam = 0x11 // AF_INET, STREAM
		addrBlock = make([]byte, 12)
		copy(addrBlock[0:4], srcIP4)
		copy(addrBlock[4:8], dstIP4)
		binary.BigEndian.PutUint16(addrBlock[8:10], uint16(srcTCP.Port))
		binary.BigEndian.PutUint16(addrBlock[10:12], uint16(dstTCP.Port))
	} else {
		srcIP6 := srcTCP.IP.To16()
		dstIP6 := dstTCP.IP.To16()
		if srcIP6 == nil || dstIP6 == nil {
			return nil, ErrUnsupportedFamily
		}
		fam = 0x21 // AF_INET6, STREAM
		addrBlock = make([]byte, 36)
		copy(addrBlock[0:16], srcIP6)
		copy(addrBlock[16:32], dstIP6)
		binary.BigEndian.PutUint16(addrBlock[32:34], uint16(srcTCP.Port))
		binary.BigEndian.PutUint16(addrBlock[34:36], uint16(dstTCP.Port))
	}

	var tlvBlock []byte
	if edgePriv != nil {
		sigPayload := buildProxyAttestationPayload(bindingID, addrBlock)
		sig, err := edgePriv.Sign(sigPayload)
		if err != nil {
			return nil, fmt.Errorf("signing PROXYv2 TLV: %w", err)
		}
		tlvBlock = make([]byte, 3+len(sig))
		tlvBlock[0] = TLVTypeEdgeAttestation
		binary.BigEndian.PutUint16(tlvBlock[1:3], uint16(len(sig)))
		copy(tlvBlock[3:], sig)
	}

	totalLen := len(addrBlock) + len(tlvBlock)
	header := make([]byte, 0, 16+totalLen)
	header = append(header, PROXYv2Signature...)
	header = append(header, 0x21) // v2, PROXY command
	header = append(header, fam)

	var addrLen [2]byte
	binary.BigEndian.PutUint16(addrLen[:], uint16(totalLen))
	header = append(header, addrLen[:]...)
	header = append(header, addrBlock...)
	header = append(header, tlvBlock...)

	return header, nil
}

// ParsePROXYv2Header parses and returns the source and destination TCP addresses from an incoming reader.
func ParsePROXYv2Header(r io.Reader) (srcAddr, dstAddr *net.TCPAddr, err error) {
	return VerifySignedPROXYv2Header(r, [16]byte{}, nil)
}

// VerifySignedPROXYv2Header parses a PROXYv2 header and, if edgePub is non-nil, verifies the
// Edge router's TLV 0xE0 attestation signature over (bindingID || addrBlock).
func VerifySignedPROXYv2Header(r io.Reader, bindingID [16]byte, edgePub ic.PubKey) (srcAddr, dstAddr *net.TCPAddr, err error) {
	var sig [12]byte
	if _, err := io.ReadFull(r, sig[:]); err != nil {
		return nil, nil, err
	}
	for i := range sig {
		if sig[i] != PROXYv2Signature[i] {
			return nil, nil, ErrInvalidProxyHeader
		}
	}

	var cmdFam [2]byte
	if _, err := io.ReadFull(r, cmdFam[:]); err != nil {
		return nil, nil, err
	}

	cmd := cmdFam[0]
	fam := cmdFam[1]

	// Check version 2
	if (cmd & 0xF0) != 0x20 {
		return nil, nil, ErrInvalidProxyHeader
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, nil, err
	}
	addrLen := binary.BigEndian.Uint16(lenBuf[:])

	addrBytes := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrBytes); err != nil {
		return nil, nil, err
	}

	if (cmd & 0x0F) == 0x00 { // LOCAL command
		return nil, nil, nil
	}

	var baseAddrLen int
	switch fam {
	case 0x11: // IPv4 STREAM
		if int(addrLen) < 12 {
			return nil, nil, ErrInvalidProxyHeader
		}
		baseAddrLen = 12
		srcIP := net.IPv4(addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3])
		dstIP := net.IPv4(addrBytes[4], addrBytes[5], addrBytes[6], addrBytes[7])
		srcPort := binary.BigEndian.Uint16(addrBytes[8:10])
		dstPort := binary.BigEndian.Uint16(addrBytes[10:12])
		srcAddr = &net.TCPAddr{IP: srcIP, Port: int(srcPort)}
		dstAddr = &net.TCPAddr{IP: dstIP, Port: int(dstPort)}
	case 0x21: // IPv6 STREAM
		if int(addrLen) < 36 {
			return nil, nil, ErrInvalidProxyHeader
		}
		baseAddrLen = 36
		srcIP := make(net.IP, 16)
		dstIP := make(net.IP, 16)
		copy(srcIP, addrBytes[0:16])
		copy(dstIP, addrBytes[16:32])
		srcPort := binary.BigEndian.Uint16(addrBytes[32:34])
		dstPort := binary.BigEndian.Uint16(addrBytes[34:36])
		srcAddr = &net.TCPAddr{IP: srcIP, Port: int(srcPort)}
		dstAddr = &net.TCPAddr{IP: dstIP, Port: int(dstPort)}
	default:
		return nil, nil, ErrUnsupportedFamily
	}

	if edgePub != nil {
		tlvs := addrBytes[baseAddrLen:]
		var foundSig []byte
		for len(tlvs) >= 3 {
			tlvType := tlvs[0]
			tlvLen := int(binary.BigEndian.Uint16(tlvs[1:3]))
			if 3+tlvLen > len(tlvs) {
				return nil, nil, ErrInvalidProxyHeader
			}
			if tlvType == TLVTypeEdgeAttestation {
				foundSig = tlvs[3 : 3+tlvLen]
				break
			}
			tlvs = tlvs[3+tlvLen:]
		}
		if len(foundSig) == 0 {
			return nil, nil, ErrInvalidProxySignature
		}
		sigPayload := buildProxyAttestationPayload(bindingID, addrBytes[:baseAddrLen])
		ok, vErr := edgePub.Verify(sigPayload, foundSig)
		if vErr != nil || !ok {
			return nil, nil, ErrInvalidProxySignature
		}
	}

	return srcAddr, dstAddr, nil
}

// PipeTCPStream executes bidirectional zero-copy piping between a client TCP connection and a libp2p stream.
func PipeTCPStream(clientConn net.Conn, stream network.Stream, bindingID [16]byte, hmacToken [16]byte, enableProxyProtocol bool, peekedBytes []byte) error {
	return PipeTCPStreamWithSigner(clientConn, stream, bindingID, hmacToken, enableProxyProtocol, peekedBytes, nil)
}

// PipeTCPStreamWithSigner executes bidirectional piping and signs the PROXYv2 header with edgePriv when provided.
func PipeTCPStreamWithSigner(clientConn net.Conn, stream network.Stream, bindingID [16]byte, hmacToken [16]byte, enableProxyProtocol bool, peekedBytes []byte, edgePriv ic.PrivKey) error {
	defer clientConn.Close()
	defer stream.Close()

	// 1. Write 32-byte preamble: [binding_id (16B) | hmac_token (16B)]
	var preamble [PreambleLength]byte
	copy(preamble[0:16], bindingID[:])
	copy(preamble[16:32], hmacToken[:])
	if _, err := stream.Write(preamble[:]); err != nil {
		return fmt.Errorf("failed to write stream preamble: %w", err)
	}

	// 2. Inject PROXYv2 header if requested
	if enableProxyProtocol {
		header, err := BuildSignedPROXYv2Header(clientConn.RemoteAddr(), clientConn.LocalAddr(), bindingID, edgePriv)
		if err == nil && len(header) > 0 {
			if _, err := stream.Write(header); err != nil {
				return fmt.Errorf("failed to write PROXYv2 header: %w", err)
			}
		}
	}

	// 3. Replay peeked bytes
	if len(peekedBytes) > 0 {
		if _, err := stream.Write(peekedBytes); err != nil {
			return fmt.Errorf("failed to write peeked bytes: %w", err)
		}
	}

	// 4. Bi-directional pipe
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Stream
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, clientConn)
		_ = stream.CloseWrite()
	}()

	// Stream -> Client
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, stream)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
	return nil
}

