package auth

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
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

	// NonceSize is 32 bytes for handshake challenges.
	NonceSize = 32

	// MaxMessageSize limits incoming auth protobuf messages to 64KB.
	MaxMessageSize = 65536
)

var (
	ErrHandshakeFailed     = errors.New("auth handshake failed")
	ErrPeerNotAuthenticated = errors.New("peer is not authenticated")
	ErrPeerRoleMismatch    = errors.New("peer role mismatch")
	ErrPeerIDMismatch      = errors.New("peer ID does not match capability manifest")
	ErrInvalidSignature    = errors.New("invalid handshake challenge signature")
	ErrMessageTooLarge     = errors.New("protobuf message exceeds max size")
)

// Authenticator handles mutual post-quantum authentication over /p2p-anycast/auth/1.0.0.
type Authenticator struct {
	mu           sync.RWMutex
	host         host.Host
	idKey        *keystore.IdentityKey
	manifest     *identity.SignedCapabilityManifest
	trustedCAPub *mldsa87.PublicKey
	sessions     map[peer.ID]*identity.IdentityClaims
}

// NewAuthenticator creates a new Authenticator.
func NewAuthenticator(h host.Host, idKey *keystore.IdentityKey, manifest *identity.SignedCapabilityManifest, trustedCAPub *mldsa87.PublicKey) *Authenticator {
	a := &Authenticator{
		host:         h,
		idKey:        idKey,
		manifest:     manifest,
		trustedCAPub: trustedCAPub,
		sessions:     make(map[peer.ID]*identity.IdentityClaims),
	}
	return a
}

// RegisterStreamHandler registers the protocol stream handler on the libp2p host (Edge side).
func (a *Authenticator) RegisterStreamHandler() {
	a.host.SetStreamHandler(ProtocolID, a.handleInboundStream)
}

// GetSession returns the verified claims for an authenticated peer.
func (a *Authenticator) GetSession(p peer.ID) (*identity.IdentityClaims, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	claims, ok := a.sessions[p]
	return claims, ok
}

// RemoveSession clears an authenticated session (e.g. on disconnect).
func (a *Authenticator) RemoveSession(p peer.ID) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, p)
}

// handleInboundStream is executed by the Edge when an Origin connects and opens /p2p-anycast/auth/1.0.0.
func (a *Authenticator) handleInboundStream(s network.Stream) {
	defer s.Close()
	remotePeer := s.Conn().RemotePeer()

	claims, err := a.serverHandshake(s, remotePeer)
	if err != nil {
		s.Reset()
		return
	}

	a.mu.Lock()
	a.sessions[remotePeer] = claims
	a.mu.Unlock()
}

// serverHandshake handles the Edge side of the mutual challenge-response.
func (a *Authenticator) serverHandshake(s network.Stream, remotePeer peer.ID) (*identity.IdentityClaims, error) {
	// 1. Read AuthHello
	var hello identity.AuthHello
	if err := readProtoMsg(s, &hello); err != nil {
		return nil, fmt.Errorf("failed to read AuthHello: %w", err)
	}

	if len(hello.NonceA) != NonceSize {
		return nil, fmt.Errorf("%w: invalid NonceA length", ErrHandshakeFailed)
	}

	// 2. Verify Origin Manifest with Root CA
	claimsA, err := manifest.VerifyManifest(hello.Manifest, a.trustedCAPub)
	if err != nil {
		return nil, fmt.Errorf("failed to verify Origin manifest: %w", err)
	}

	if claimsA.Libp2PPeerId != remotePeer.String() {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrPeerIDMismatch, remotePeer.String(), claimsA.Libp2PPeerId)
	}

	if claimsA.Role != identity.NodeRole_ORIGIN_NODE {
		return nil, fmt.Errorf("%w: expected ORIGIN_NODE, got %v", ErrPeerRoleMismatch, claimsA.Role)
	}

	// 3. Generate NonceB and sign NonceA
	nonceB := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonceB); err != nil {
		return nil, err
	}

	sigA, err := a.idKey.SignWithContext(hello.NonceA, mldsa.ContextNodeAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to sign NonceA: %w", err)
	}

	// Send AuthChallenge
	challenge := &identity.AuthChallenge{
		NonceB:     nonceB,
		Manifest:   a.manifest,
		SignatureA: sigA,
	}
	if err := writeProtoMsg(s, challenge); err != nil {
		return nil, fmt.Errorf("failed to write AuthChallenge: %w", err)
	}

	// 4. Read AuthComplete
	var complete identity.AuthComplete
	if err := readProtoMsg(s, &complete); err != nil {
		return nil, fmt.Errorf("failed to read AuthComplete: %w", err)
	}

	// 5. Verify Origin's signature over NonceB
	originPubKey, err := mldsa.PublicKeyFromBytes(claimsA.SubjectMldsaPubkey)
	if err != nil {
		return nil, fmt.Errorf("invalid Origin public key in claims: %w", err)
	}

	if !mldsa.Verify(originPubKey, nonceB, mldsa.ContextNodeAuth, complete.SignatureB) {
		return nil, fmt.Errorf("%w: Origin signature over NonceB failed verification", ErrInvalidSignature)
	}

	return claimsA, nil
}

// AuthenticateOutbound is executed by the Origin to authenticate against an Edge router.
func (a *Authenticator) AuthenticateOutbound(ctx context.Context, edgePeer peer.ID) (*identity.IdentityClaims, error) {
	s, err := a.host.NewStream(ctx, edgePeer, ProtocolID)
	if err != nil {
		return nil, fmt.Errorf("failed to open auth stream to edge %s: %w", edgePeer, err)
	}
	defer s.Close()

	// 1. Generate NonceA and send AuthHello
	nonceA := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonceA); err != nil {
		s.Reset()
		return nil, err
	}

	hello := &identity.AuthHello{
		NonceA:   nonceA,
		Manifest: a.manifest,
	}
	if err := writeProtoMsg(s, hello); err != nil {
		s.Reset()
		return nil, fmt.Errorf("failed to write AuthHello: %w", err)
	}

	// 2. Read AuthChallenge
	var challenge identity.AuthChallenge
	if err := readProtoMsg(s, &challenge); err != nil {
		s.Reset()
		return nil, fmt.Errorf("failed to read AuthChallenge: %w", err)
	}

	if len(challenge.NonceB) != NonceSize {
		s.Reset()
		return nil, fmt.Errorf("%w: invalid NonceB length", ErrHandshakeFailed)
	}

	// 3. Verify Edge Manifest with Root CA
	claimsB, err := manifest.VerifyManifest(challenge.Manifest, a.trustedCAPub)
	if err != nil {
		s.Reset()
		return nil, fmt.Errorf("failed to verify Edge manifest: %w", err)
	}

	if claimsB.Libp2PPeerId != edgePeer.String() {
		s.Reset()
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrPeerIDMismatch, edgePeer.String(), claimsB.Libp2PPeerId)
	}

	if claimsB.Role != identity.NodeRole_EDGE_ROUTER {
		s.Reset()
		return nil, fmt.Errorf("%w: expected EDGE_ROUTER, got %v", ErrPeerRoleMismatch, claimsB.Role)
	}

	// 4. Verify Edge's signature over NonceA
	edgePubKey, err := mldsa.PublicKeyFromBytes(claimsB.SubjectMldsaPubkey)
	if err != nil {
		s.Reset()
		return nil, fmt.Errorf("invalid Edge public key in claims: %w", err)
	}

	if !mldsa.Verify(edgePubKey, nonceA, mldsa.ContextNodeAuth, challenge.SignatureA) {
		s.Reset()
		return nil, fmt.Errorf("%w: Edge signature over NonceA failed verification", ErrInvalidSignature)
	}

	// 5. Sign NonceB and send AuthComplete
	sigB, err := a.idKey.SignWithContext(challenge.NonceB, mldsa.ContextNodeAuth)
	if err != nil {
		s.Reset()
		return nil, fmt.Errorf("failed to sign NonceB: %w", err)
	}

	complete := &identity.AuthComplete{
		SignatureB: sigB,
	}
	if err := writeProtoMsg(s, complete); err != nil {
		s.Reset()
		return nil, fmt.Errorf("failed to write AuthComplete: %w", err)
	}

	a.mu.Lock()
	a.sessions[edgePeer] = claimsB
	a.mu.Unlock()

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
