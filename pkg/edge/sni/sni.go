package sni

import (
	"encoding/binary"
	"errors"
)

var (
	ErrNotTLSHandshake = errors.New("packet is not a TLS handshake record")
	ErrUnsupportedTLS  = errors.New("unsupported TLS record version")
	ErrTruncatedRecord = errors.New("TLS record is truncated")
	ErrNotClientHello  = errors.New("TLS handshake is not ClientHello")
	ErrNoSNIExtension  = errors.New("no RFC 6066 SNI extension found")
	ErrMalformedSNI    = errors.New("malformed SNI extension")
)

// ExtractSNI inspects a raw byte slice containing the start of a TLS connection
// and extracts the RFC 6066 Server Name Indication (SNI) hostname without completing
// the handshake and with zero heap allocations during traversal.
func ExtractSNI(data []byte) (string, error) {
	// Need at least 5 bytes for TLS record header
	if len(data) < 5 {
		return "", ErrTruncatedRecord
	}

	// 1. Verify Record Type == Handshake (0x16)
	if data[0] != 0x16 {
		return "", ErrNotTLSHandshake
	}

	// 2. Verify TLS Major/Minor version (0x03, 0x01..0x03)
	major := data[1]
	minor := data[2]
	if major != 0x03 || minor < 0x01 || minor > 0x03 {
		return "", ErrUnsupportedTLS
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		// Use available bytes up to len(data) if we have enough for ClientHello headers
		if len(data) < 44 {
			return "", ErrTruncatedRecord
		}
	}

	offset := 5

	// 3. Handshake Type == ClientHello (0x01)
	if offset >= len(data) || data[offset] != 0x01 {
		return "", ErrNotClientHello
	}
	offset++ // Skip handshake type (1B)

	// Skip Handshake Length (3B)
	if offset+3 > len(data) {
		return "", ErrTruncatedRecord
	}
	offset += 3

	// Skip Client Version (2B) + Random (32B)
	if offset+34 > len(data) {
		return "", ErrTruncatedRecord
	}
	offset += 34

	// Session ID Length (1B)
	if offset >= len(data) {
		return "", ErrTruncatedRecord
	}
	sessionIDLen := int(data[offset])
	offset++
	if offset+sessionIDLen > len(data) {
		return "", ErrTruncatedRecord
	}
	offset += sessionIDLen

	// Cipher Suites Length (2B)
	if offset+2 > len(data) {
		return "", ErrTruncatedRecord
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+cipherSuitesLen > len(data) {
		return "", ErrTruncatedRecord
	}
	offset += cipherSuitesLen

	// Compression Methods Length (1B)
	if offset >= len(data) {
		return "", ErrTruncatedRecord
	}
	compressionMethodsLen := int(data[offset])
	offset++
	if offset+compressionMethodsLen > len(data) {
		return "", ErrTruncatedRecord
	}
	offset += compressionMethodsLen

	// Check if extensions are present (2B length)
	if offset >= len(data) {
		return "", ErrNoSNIExtension
	}
	if offset+2 > len(data) {
		return "", ErrTruncatedRecord
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	extensionsEnd := offset + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	// Iterate extensions looking for extension 0x0000 (server_name)
	for offset+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > extensionsEnd {
			return "", ErrTruncatedRecord
		}

		if extType == 0x0000 {
			// RFC 6066 Server Name Indication
			// ServerNameList length (2B)
			if extLen < 2 {
				return "", ErrMalformedSNI
			}
			listLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			listOffset := offset + 2
			listEnd := listOffset + listLen
			if listEnd > offset+extLen {
				return "", ErrMalformedSNI
			}

			for listOffset+3 <= listEnd {
				nameType := data[listOffset]
				nameLen := int(binary.BigEndian.Uint16(data[listOffset+1 : listOffset+3]))
				listOffset += 3

				if listOffset+nameLen > listEnd {
					return "", ErrMalformedSNI
				}

				if nameType == 0x00 { // host_name
					return string(data[listOffset : listOffset+nameLen]), nil
				}
				listOffset += nameLen
			}
			return "", ErrNoSNIExtension
		}

		offset += extLen
	}

	return "", ErrNoSNIExtension
}
