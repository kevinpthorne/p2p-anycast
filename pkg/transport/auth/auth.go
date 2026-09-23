package auth

import (
	"context"
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
	identity "p2p-anycast/pkg/proto/identity"
)

const (
	// ProtocolID is the libp2p protocol ID for node authentication.
	ProtocolID = "/p2p-anycast/auth/1.0.0"

	// MaxMessageSize limits incoming auth protobuf messages to 64KB.
	MaxMessageSize = 65536
)

var (
	ErrHandshakeFailed     = errors.New("auth handshake failed")
	ErrPeerNotAuthenticated = errors.New("peer is not authenticated")
	ErrPeerRoleMismatch    = errors.New("peer role mismatch")
	ErrPeerIDMismatch      = errors.New("peer ID does not match capability manifest")
	ErrMessageTooLarge     = errors.New("protobuf message exceeds max size")
)

// Authenticator handles mutual manifest-based authentication over /p2p-anycast/auth/1.0.0.
// Identity verification is delegated to the libp2p transport (QUIC/Noise), which
// cryptographically proves peer ownership of the key behind their Peer ID.
// This layer verifies that each peer holds a CA-signed capability manifest for their Peer ID.
type Authenticator struct {
	mu           sync.RWMutex
	host         host.Host
	idKey        *keystore.IdentityKey
	manifest     *identity.SignedCapabilityManifest
	trustedCAPub *mldsa87.PublicKey
	sessions     map[peer.ID]*identity.IdentityClaims
}

// NewAuthenticator creates a new Authenticator.
func NewAuthenticator(h host.Host, idKey *keystore.IdentityKey, mfest *identity.SignedCapabilityManifest, trustedCAPub *mldsa87.PublicKey) *Authenticator {
	return &Authenticator{
		host:         h,
		idKey:        idKey,
		manifest:     mfest,
		trustedCAPub: trustedCAPub,
		sessions:     make(map[peer.ID]*identity.IdentityClaims),
	}
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

// serverHandshake handles the Edge side of mutual manifest exchange.
// The libp2p transport has already proven the remote peer owns the key behind their Peer ID;
// we simply verify their manifest is CA-signed and matches that Peer ID.
func (a *Authenticator) serverHandshake(s network.Stream, remotePeer peer.ID) (*identity.IdentityClaims, error) {
	// 1. Read AuthHello from Origin
	var hello identity.AuthHello
	if err := readProtoMsg(s, &hello); err != nil {
		return nil, fmt.Errorf("failed to read AuthHello: %w", err)
	}

	// 2. Verify Origin's manifest with Root CA
	claimsA, err := manifest.VerifyManifest(hello.Manifest, a.trustedCAPub)
	if err != nil {
		return nil, fmt.Errorf("failed to verify Origin manifest: %w", err)
	}

	if claimsA.Libp2PPeerId != remotePeer.String() {
		return nil, fmt.Errorf("%w: manifest peer ID %s does not match connected peer %s",
			ErrPeerIDMismatch, claimsA.Libp2PPeerId, remotePeer.String())
	}

	if claimsA.Role != identity.NodeRole_ORIGIN_NODE {
		return nil, fmt.Errorf("%w: expected ORIGIN_NODE, got %v", ErrPeerRoleMismatch, claimsA.Role)
	}

	// 3. Send AuthResponse with Edge's own manifest
	resp := &identity.AuthResponse{Manifest: a.manifest}
	if err := writeProtoMsg(s, resp); err != nil {
		return nil, fmt.Errorf("failed to write AuthResponse: %w", err)
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

	// 1. Send AuthHello with Origin's manifest
	hello := &identity.AuthHello{Manifest: a.manifest}
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

	if claimsB.Libp2PPeerId != edgePeer.String() {
		s.Reset()
		return nil, fmt.Errorf("%w: manifest peer ID %s does not match connected peer %s",
			ErrPeerIDMismatch, claimsB.Libp2PPeerId, edgePeer.String())
	}

	if claimsB.Role != identity.NodeRole_EDGE_ROUTER {
		s.Reset()
		return nil, fmt.Errorf("%w: expected EDGE_ROUTER, got %v", ErrPeerRoleMismatch, claimsB.Role)
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
