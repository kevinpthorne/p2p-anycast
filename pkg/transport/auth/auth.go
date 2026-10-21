package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	"p2p-anycast/pkg/pki/keystore"
	"p2p-anycast/pkg/pki/manifest"
	"p2p-anycast/pkg/pki/mldsa"
	identity "p2p-anycast/pkg/proto/identity"
)

const (
	// ProtocolID is the libp2p protocol ID for node authentication.
	ProtocolID = "/p2p-anycast/auth/1.0.0"

	// MaxMessageSize limits incoming auth protobuf messages to 64KB.
	MaxMessageSize = 65536

	// AuthNonceSize is the required CSPRNG challenge nonce length in bytes.
	AuthNonceSize = 32

	// MaxClockSkewSec is the maximum allowed clock skew (5 minutes) for auth handshakes.
	MaxClockSkewSec = 300

	// HandshakeTimeout is the per-stream deadline for completing the auth handshake.
	HandshakeTimeout = 10 * time.Second
)

var (
	ErrHandshakeFailed      = errors.New("auth handshake failed")
	ErrPeerNotAuthenticated = errors.New("peer is not authenticated")
	ErrPeerRoleMismatch     = errors.New("peer role mismatch")
	ErrPeerIDMismatch       = errors.New("peer ID does not match capability manifest")
	ErrMessageTooLarge      = errors.New("protobuf message exceeds max size")
	ErrInvalidAuthChallenge = errors.New("invalid auth challenge nonce, timestamp, or signature")
)

// AuthReceipt is a non-repudiable cryptographic record of a completed mutual authentication handshake.
type AuthReceipt struct {
	PeerID        peer.ID
	Claims        *identity.IdentityClaims
	LocalNonce    []byte
	RemoteNonce   []byte
	Timestamp     int64
	PeerSignature []byte
}

// Authenticator handles mutual manifest-based and challenge-response authentication over /p2p-anycast/auth/1.0.0.
type Authenticator struct {
	mu             sync.RWMutex
	host           host.Host
	idKey          *keystore.IdentityKey
	manifest       *identity.SignedCapabilityManifest
	trustedCAPub   *mldsa87.PublicKey
	revocationList *manifest.RevocationList
	sessions       map[peer.ID]*identity.IdentityClaims
	receipts       map[peer.ID]*AuthReceipt
}

// NewAuthenticator creates a new Authenticator and registers a disconnect listener to evict terminated sessions.
func NewAuthenticator(h host.Host, idKey *keystore.IdentityKey, mfest *identity.SignedCapabilityManifest, trustedCAPub *mldsa87.PublicKey) *Authenticator {
	a := &Authenticator{
		host:           h,
		idKey:          idKey,
		manifest:       mfest,
		trustedCAPub:   trustedCAPub,
		revocationList: manifest.NewRevocationList(),
		sessions:       make(map[peer.ID]*identity.IdentityClaims),
		receipts:       make(map[peer.ID]*AuthReceipt),
	}

	if h != nil {
		h.Network().Notify(&network.NotifyBundle{
			DisconnectedF: func(net network.Network, conn network.Conn) {
				remotePeer := conn.RemotePeer()
				if len(net.ConnsToPeer(remotePeer)) == 0 {
					a.RemoveSession(remotePeer)
				}
			},
		})
	}

	return a
}

// SetRevocationList configures the RevocationList used to reject revoked manifests/peers at handshake and runtime.
func (a *Authenticator) SetRevocationList(rl *manifest.RevocationList) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revocationList = rl
}

// RevocationList returns the Authenticator's active RevocationList.
func (a *Authenticator) RevocationList() *manifest.RevocationList {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.revocationList
}

// RegisterStreamHandler registers the protocol stream handler on the libp2p host (Edge side).
func (a *Authenticator) RegisterStreamHandler() {
	a.host.SetStreamHandler(ProtocolID, a.handleInboundStream)
}

// GetSession returns the verified claims for an authenticated peer, enforcing runtime expiration and revocation.
func (a *Authenticator) GetSession(p peer.ID) (*identity.IdentityClaims, bool) {
	a.mu.RLock()
	claims, ok := a.sessions[p]
	rl := a.revocationList
	a.mu.RUnlock()
	if !ok || claims == nil {
		return nil, false
	}

	now := time.Now().Unix()
	if now > claims.NotAfter || (rl != nil && rl.IsRevoked(claims)) {
		a.RemoveSession(p)
		return nil, false
	}

	return claims, true
}

// GetReceipt returns the cryptographic non-repudiation receipt for an authenticated peer.
func (a *Authenticator) GetReceipt(p peer.ID) (*AuthReceipt, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	r, ok := a.receipts[p]
	return r, ok
}

// RemoveSession clears an authenticated session (e.g. on disconnect or revocation).
func (a *Authenticator) RemoveSession(p peer.ID) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, p)
	delete(a.receipts, p)
}

// handleInboundStream is executed by the Edge when an Origin connects and opens /p2p-anycast/auth/1.0.0.
func (a *Authenticator) handleInboundStream(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(HandshakeTimeout))
	remotePeer := s.Conn().RemotePeer()

	claims, receipt, err := a.serverHandshake(s, remotePeer)
	if err != nil {
		log.Printf("[Auth] Inbound authentication failed from peer %s: %v", remotePeer, err)
		s.Reset()
		return
	}

	log.Printf("[Auth] Peer %s authenticated successfully (Subject: %q, Role: %v)",
		remotePeer, claims.SubjectId, claims.Role)

	a.mu.Lock()
	a.sessions[remotePeer] = claims
	a.receipts[remotePeer] = receipt
	a.mu.Unlock()

	a.evictStaleConns(remotePeer, s.Conn())
}

func (a *Authenticator) evictStaleConns(peerID peer.ID, activeConn network.Conn) {
	if a.host == nil || activeConn == nil {
		return
	}
	for _, c := range a.host.Network().ConnsToPeer(peerID) {
		if c != activeConn {
			_ = c.Close()
		}
	}
}

func extractPeerPubKey(s network.Stream, peerID peer.ID) (ic.PubKey, error) {
	if s != nil && s.Conn() != nil {
		if pub := s.Conn().RemotePublicKey(); pub != nil {
			return pub, nil
		}
	}
	return peerID.ExtractPublicKey()
}

func buildAuthHelloSigningPayload(nonceA []byte, timestamp int64, originPeer, edgePeer peer.ID, manifestSig []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(mldsa.ContextNodeAuth)
	buf.WriteByte(0)
	buf.WriteString("HELLO")
	buf.WriteByte(0)
	buf.Write(nonceA)
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(timestamp))
	buf.Write(tsBuf[:])
	buf.WriteString(originPeer.String())
	buf.WriteByte(0)
	buf.WriteString(edgePeer.String())
	buf.WriteByte(0)
	buf.Write(manifestSig)
	return buf.Bytes()
}

func buildAuthResponseSigningPayload(nonceA, nonceB []byte, timestamp int64, edgePeer, originPeer peer.ID, manifestSig []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(mldsa.ContextNodeAuth)
	buf.WriteByte(0)
	buf.WriteString("RESPONSE")
	buf.WriteByte(0)
	buf.Write(nonceA)
	buf.Write(nonceB)
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(timestamp))
	buf.Write(tsBuf[:])
	buf.WriteString(edgePeer.String())
	buf.WriteByte(0)
	buf.WriteString(originPeer.String())
	buf.WriteByte(0)
	buf.Write(manifestSig)
	return buf.Bytes()
}

func isTimestampFresh(ts int64) bool {
	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	return diff <= MaxClockSkewSec
}

// serverHandshake handles the Edge side of mutual manifest and signed challenge-response exchange.
func (a *Authenticator) serverHandshake(s network.Stream, remotePeer peer.ID) (*identity.IdentityClaims, *AuthReceipt, error) {
	// 1. Read AuthHello from Origin
	var hello identity.AuthHello
	if err := readProtoMsg(s, &hello); err != nil {
		return nil, nil, fmt.Errorf("failed to read AuthHello: %w", err)
	}

	// 2. Verify Origin's manifest with Root CA
	claimsA, err := manifest.VerifyManifest(hello.Manifest, a.trustedCAPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify Origin manifest: %w", err)
	}

	if rl := a.RevocationList(); rl != nil && rl.IsRevoked(claimsA) {
		return nil, nil, manifest.ErrRevokedManifest
	}

	if claimsA.Libp2PPeerId != remotePeer.String() {
		return nil, nil, fmt.Errorf("%w: manifest peer ID %s does not match connected peer %s",
			ErrPeerIDMismatch, claimsA.Libp2PPeerId, remotePeer.String())
	}

	if claimsA.Role != identity.NodeRole_ORIGIN_NODE {
		return nil, nil, fmt.Errorf("%w: expected ORIGIN_NODE, got %v", ErrPeerRoleMismatch, claimsA.Role)
	}

	// 3. Verify Origin's challenge nonce, timestamp, and non-repudiation signature
	if len(hello.Nonce) != AuthNonceSize || !isTimestampFresh(hello.Timestamp) || len(hello.Signature) == 0 {
		return nil, nil, fmt.Errorf("%w: invalid AuthHello nonce or timestamp", ErrInvalidAuthChallenge)
	}

	remotePub, err := extractPeerPubKey(s, remotePeer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract Origin public key: %w", err)
	}

	expectedHelloPayload := buildAuthHelloSigningPayload(hello.Nonce, hello.Timestamp, remotePeer, a.host.ID(), hello.Manifest.CaSignature)
	sigOk, err := remotePub.Verify(expectedHelloPayload, hello.Signature)
	if err != nil || !sigOk {
		return nil, nil, fmt.Errorf("%w: Origin signature verification failed", ErrInvalidAuthChallenge)
	}

	// 4. Generate Edge's challenge response and sign over both nonces
	nonceB := make([]byte, AuthNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonceB); err != nil {
		return nil, nil, fmt.Errorf("failed to generate Edge nonce: %w", err)
	}
	tsB := time.Now().Unix()

	var manifestSig []byte
	if a.manifest != nil {
		manifestSig = a.manifest.CaSignature
	}
	respPayload := buildAuthResponseSigningPayload(hello.Nonce, nonceB, tsB, a.host.ID(), remotePeer, manifestSig)
	sigB, err := a.idKey.Libp2pPrivKey().Sign(respPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign AuthResponse: %w", err)
	}

	resp := &identity.AuthResponse{
		Manifest:  a.manifest,
		Nonce:     nonceB,
		Timestamp: tsB,
		Signature: sigB,
	}
	if err := writeProtoMsg(s, resp); err != nil {
		return nil, nil, fmt.Errorf("failed to write AuthResponse: %w", err)
	}

	receipt := &AuthReceipt{
		PeerID:        remotePeer,
		Claims:        claimsA,
		LocalNonce:    nonceB,
		RemoteNonce:   hello.Nonce,
		Timestamp:     hello.Timestamp,
		PeerSignature: hello.Signature,
	}

	return claimsA, receipt, nil
}

// AuthenticateOutbound is executed by the Origin to authenticate against an Edge router.
func (a *Authenticator) AuthenticateOutbound(ctx context.Context, edgePeer peer.ID) (*identity.IdentityClaims, error) {
	s, err := a.host.NewStream(ctx, edgePeer, ProtocolID)
	if err != nil {
		return nil, fmt.Errorf("failed to open auth stream to edge %s: %w", edgePeer, err)
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(HandshakeTimeout))

	// 1. Generate Origin challenge nonce and sign AuthHello
	nonceA := make([]byte, AuthNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonceA); err != nil {
		s.Reset()
		return nil, fmt.Errorf("failed to generate Origin nonce: %w", err)
	}
	tsA := time.Now().Unix()

	var manifestSig []byte
	if a.manifest != nil {
		manifestSig = a.manifest.CaSignature
	}
	helloPayload := buildAuthHelloSigningPayload(nonceA, tsA, a.host.ID(), edgePeer, manifestSig)
	sigA, err := a.idKey.Libp2pPrivKey().Sign(helloPayload)
	if err != nil {
		s.Reset()
		return nil, fmt.Errorf("failed to sign AuthHello: %w", err)
	}

	hello := &identity.AuthHello{
		Manifest:  a.manifest,
		Nonce:     nonceA,
		Timestamp: tsA,
		Signature: sigA,
	}
	if err := writeProtoMsg(s, hello); err != nil {
		s.Reset()
		return nil, fmt.Errorf("failed to write AuthHello: %w", err)
	}

	// 2. Read AuthResponse from Edge
	var resp identity.AuthResponse
	if err := readProtoMsg(s, &resp); err != nil {
		s.Reset()
		return nil, fmt.Errorf("failed to read AuthResponse: %w", err)
	}

	// 3. Verify Edge's manifest with Root CA
	claimsB, err := manifest.VerifyManifest(resp.Manifest, a.trustedCAPub)
	if err != nil {
		s.Reset()
		return nil, fmt.Errorf("failed to verify Edge manifest: %w", err)
	}

	if rl := a.RevocationList(); rl != nil && rl.IsRevoked(claimsB) {
		s.Reset()
		return nil, manifest.ErrRevokedManifest
	}

	if claimsB.Libp2PPeerId != edgePeer.String() {
		s.Reset()
		return nil, fmt.Errorf("%w: manifest peer ID %s does not match connected peer %s",
			ErrPeerIDMismatch, claimsB.Libp2PPeerId, edgePeer.String())
	}

	if claimsB.Role != identity.NodeRole_EDGE_ROUTER {
		s.Reset()
		return nil, fmt.Errorf("%w: expected EDGE_ROUTER, got %v", ErrPeerRoleMismatch, claimsB.Role)
	}

	// 4. Verify Edge's challenge response nonce, timestamp, and non-repudiation signature bound to nonceA
	if len(resp.Nonce) != AuthNonceSize || !isTimestampFresh(resp.Timestamp) || len(resp.Signature) == 0 {
		s.Reset()
		return nil, fmt.Errorf("%w: invalid AuthResponse nonce or timestamp", ErrInvalidAuthChallenge)
	}

	edgePub, err := extractPeerPubKey(s, edgePeer)
	if err != nil {
		s.Reset()
		return nil, fmt.Errorf("failed to extract Edge public key: %w", err)
	}

	expectedRespPayload := buildAuthResponseSigningPayload(nonceA, resp.Nonce, resp.Timestamp, edgePeer, a.host.ID(), resp.Manifest.CaSignature)
	sigOk, err := edgePub.Verify(expectedRespPayload, resp.Signature)
	if err != nil || !sigOk {
		s.Reset()
		return nil, fmt.Errorf("%w: Edge signature verification failed", ErrInvalidAuthChallenge)
	}

	receipt := &AuthReceipt{
		PeerID:        edgePeer,
		Claims:        claimsB,
		LocalNonce:    nonceA,
		RemoteNonce:   resp.Nonce,
		Timestamp:     resp.Timestamp,
		PeerSignature: resp.Signature,
	}

	a.mu.Lock()
	a.sessions[edgePeer] = claimsB
	a.receipts[edgePeer] = receipt
	a.mu.Unlock()

	a.evictStaleConns(edgePeer, s.Conn())

	return claimsB, nil
}

func writeProtoMsg(w io.Writer, msg proto.Message) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	if len(data) > MaxMessageSize {
		return ErrMessageTooLarge
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	return nil
}

func readProtoMsg(r io.Reader, msg proto.Message) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return err
	}

	msgLen := binary.BigEndian.Uint32(lenBuf[:])
	if msgLen > MaxMessageSize {
		return ErrMessageTooLarge
	}

	buf := make([]byte, msgLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}

	return proto.Unmarshal(buf, msg)
}

