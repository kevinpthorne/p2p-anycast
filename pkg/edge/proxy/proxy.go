package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/libp2p/go-libp2p/core/network"
)

const (
	// TCPProtocolID is the libp2p protocol ID for proxied TCP streams.
	TCPProtocolID = "/p2p-anycast/tcp/1.0.0"

	// PreambleLength is 32 bytes: 16 bytes binding_id + 16 bytes hmac_token.
	PreambleLength = 32
)

var (
	// PROXYv2Signature is the 12-byte constant header for PROXY protocol v2.
	PROXYv2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

	ErrInvalidProxyHeader = errors.New("invalid PROXYv2 header")
	ErrUnsupportedFamily  = errors.New("unsupported address family for PROXYv2")
)

// BuildPROXYv2Header creates a binary PROXYv2 header representing the client and edge endpoints.
func BuildPROXYv2Header(srcAddr, dstAddr net.Addr) ([]byte, error) {
	srcTCP, ok1 := srcAddr.(*net.TCPAddr)
	dstTCP, ok2 := dstAddr.(*net.TCPAddr)
	if !ok1 || !ok2 {
		return nil, errors.New("addresses must be *net.TCPAddr")
	}

	srcIP4 := srcTCP.IP.To4()
	dstIP4 := dstTCP.IP.To4()

	var header []byte
	header = append(header, PROXYv2Signature...)
	header = append(header, 0x21) // v2, PROXY command

	if srcIP4 != nil && dstIP4 != nil {
		// IPv4 TCP
		header = append(header, 0x11) // AF_INET, STREAM
		var addrLen [2]byte
		binary.BigEndian.PutUint16(addrLen[:], 12) // 4 + 4 + 2 + 2 = 12 bytes
		header = append(header, addrLen[:]...)

		header = append(header, srcIP4...)
		header = append(header, dstIP4...)

		var portBuf [4]byte
		binary.BigEndian.PutUint16(portBuf[0:2], uint16(srcTCP.Port))
		binary.BigEndian.PutUint16(portBuf[2:4], uint16(dstTCP.Port))
		header = append(header, portBuf[:]...)
	} else {
		// IPv6 TCP
		srcIP6 := srcTCP.IP.To16()
		dstIP6 := dstTCP.IP.To16()
		if srcIP6 == nil || dstIP6 == nil {
			return nil, ErrUnsupportedFamily
		}

		header = append(header, 0x21) // AF_INET6, STREAM
		var addrLen [2]byte
		binary.BigEndian.PutUint16(addrLen[:], 36) // 16 + 16 + 2 + 2 = 36 bytes
		header = append(header, addrLen[:]...)

		header = append(header, srcIP6...)
		header = append(header, dstIP6...)

		var portBuf [4]byte
		binary.BigEndian.PutUint16(portBuf[0:2], uint16(srcTCP.Port))
		binary.BigEndian.PutUint16(portBuf[2:4], uint16(dstTCP.Port))
		header = append(header, portBuf[:]...)
	}

	return header, nil
}

// ParsePROXYv2Header parses and returns the source and destination TCP addresses from an incoming reader.
func ParsePROXYv2Header(r io.Reader) (srcAddr, dstAddr *net.TCPAddr, err error) {
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

	if fam == 0x11 { // IPv4 STREAM
		if addrLen < 12 {
			return nil, nil, ErrInvalidProxyHeader
		}
		srcIP := net.IPv4(addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3])
		dstIP := net.IPv4(addrBytes[4], addrBytes[5], addrBytes[6], addrBytes[7])
		srcPort := binary.BigEndian.Uint16(addrBytes[8:10])
		dstPort := binary.BigEndian.Uint16(addrBytes[10:12])

		return &net.TCPAddr{IP: srcIP, Port: int(srcPort)}, &net.TCPAddr{IP: dstIP, Port: int(dstPort)}, nil
	} else if fam == 0x21 { // IPv6 STREAM
		if addrLen < 36 {
			return nil, nil, ErrInvalidProxyHeader
		}
		srcIP := make(net.IP, 16)
		dstIP := make(net.IP, 16)
		copy(srcIP, addrBytes[0:16])
		copy(dstIP, addrBytes[16:32])
		srcPort := binary.BigEndian.Uint16(addrBytes[32:34])
		dstPort := binary.BigEndian.Uint16(addrBytes[34:36])

		return &net.TCPAddr{IP: srcIP, Port: int(srcPort)}, &net.TCPAddr{IP: dstIP, Port: int(dstPort)}, nil
	}

	return nil, nil, ErrUnsupportedFamily
}

// PipeTCPStream executes bidirectional zero-copy piping between a client TCP connection and a libp2p stream.
func PipeTCPStream(clientConn net.Conn, stream network.Stream, bindingID [16]byte, hmacToken [16]byte, enableProxyProtocol bool, peekedBytes []byte) error {
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
		header, err := BuildPROXYv2Header(clientConn.RemoteAddr(), clientConn.LocalAddr())
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
