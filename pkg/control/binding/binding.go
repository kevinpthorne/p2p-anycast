package binding

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"

	"lukechampine.com/blake3"

	control "p2p-anycast/pkg/proto/control"
)

// DeriveBindingID computes the deterministic 128-bit BLAKE3 binding_id.
// binding_id = Truncate_128(BLAKE3(service_id || protocol || public_port || sni_hostname))
func DeriveBindingID(serviceID string, protocol control.TransportProtocol, publicPort uint32, sniHostname string) [16]byte {
	h := blake3.New(32, nil)

	// service_id
	h.Write([]byte(serviceID))

	// protocol (1 byte)
	h.Write([]byte{byte(protocol)})

	// public_port (4 bytes, big-endian)
	var portBuf [4]byte
	binary.BigEndian.PutUint32(portBuf[:], publicPort)
	h.Write(portBuf[:])

	// sni_hostname
	h.Write([]byte(sniHostname))

	sum := h.Sum(nil)
	var bindingID [16]byte
	copy(bindingID[:], sum[:16])
	return bindingID
}

// GenerateHMAC computes the connection-scoped 128-bit HMAC capability token.
// HMAC = Truncate_128(HMAC-SHA256(K_origin, EdgePeerID || public_port || binding_id))
func GenerateHMAC(originKey []byte, edgePeerID string, publicPort uint32, bindingID [16]byte) [16]byte {
	mac := hmac.New(sha256.New, originKey)
	mac.Write([]byte(edgePeerID))

	var portBuf [4]byte
	binary.BigEndian.PutUint32(portBuf[:], publicPort)
	mac.Write(portBuf[:])

	mac.Write(bindingID[:])

	sum := mac.Sum(nil)
	var token [16]byte
	copy(token[:], sum[:16])
	return token
}

// VerifyHMAC validates an incoming 16-byte HMAC token in constant time.
func VerifyHMAC(originKey []byte, edgePeerID string, publicPort uint32, bindingID [16]byte, token []byte) bool {
	if len(token) != 16 {
		return false
	}
	expected := GenerateHMAC(originKey, edgePeerID, publicPort, bindingID)
	return subtle.ConstantTimeCompare(expected[:], token) == 1
}
