package gossip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	control "p2p-anycast/pkg/proto/control"
)

const (
	// RegistryTopic is the GossipSub topic for service registration and routing announcements.
	RegistryTopic = "/p2p-anycast/registry/1.0.0"

	// DirectRegisterProtocolID is the point-to-point libp2p stream protocol used for immediate
	// deterministic registration synchronization upon connection/authentication.
	DirectRegisterProtocolID = "/p2p-anycast/register/1.0.0"

	// MaxRegistrationMsgSize limits individual registration protobuf messages to 64KB.
	MaxRegistrationMsgSize = 65536

	// ContextControlRegistration is the domain separation context for Origin control-plane signatures.
	ContextControlRegistration = "p2p-anycast:control:reg:v1"

	// MaxRegistrationSkewSec is the maximum clock skew / replay window (5 minutes) for signed registrations.
	MaxRegistrationSkewSec = 300

	// DirectStreamReadTimeout is the per-frame read deadline on direct registration streams.
	DirectStreamReadTimeout = 5 * time.Second
)

var (
	ErrInvalidOriginSignature = errors.New("invalid or missing origin non-repudiation signature on ServiceRegistration")
	ErrStaleRegistration      = errors.New("service registration timestamp is outside allowed replay window")
)

// SignRegistration signs a ServiceRegistration using the Origin's libp2p private key for non-repudiation.
func SignRegistration(reg *control.ServiceRegistration, priv ic.PrivKey) error {
	if reg == nil || priv == nil {
		return errors.New("registration and private key must not be nil")
	}
	if reg.Timestamp == 0 {
		reg.Timestamp = time.Now().Unix()
	}

	payload, err := buildRegistrationSigningPayload(reg)
	if err != nil {
		return err
	}

	sig, err := priv.Sign(payload)
	if err != nil {
		return fmt.Errorf("signing ServiceRegistration: %w", err)
	}
	reg.OriginSignature = sig
	return nil
}

// VerifyRegistration verifies the non-repudiable OriginSignature and freshness of a ServiceRegistration.
func VerifyRegistration(reg *control.ServiceRegistration) error {
	if reg == nil || reg.OriginPeerId == "" || len(reg.OriginSignature) == 0 {
		return ErrInvalidOriginSignature
	}

	now := time.Now().Unix()
	diff := now - reg.Timestamp
	if diff < 0 {
		diff = -diff
	}
	if reg.Timestamp == 0 || diff > MaxRegistrationSkewSec {
		return ErrStaleRegistration
	}

	originPeer, err := peer.Decode(reg.OriginPeerId)
	if err != nil {
		return fmt.Errorf("%w: invalid OriginPeerId: %v", ErrInvalidOriginSignature, err)
	}
	pubKey, err := originPeer.ExtractPublicKey()
	if err != nil || pubKey == nil {
		return fmt.Errorf("%w: cannot extract public key from OriginPeerId: %v", ErrInvalidOriginSignature, err)
	}

	payload, err := buildRegistrationSigningPayload(reg)
	if err != nil {
		return err
	}

	ok, err := pubKey.Verify(payload, reg.OriginSignature)
	if err != nil || !ok {
		return ErrInvalidOriginSignature
	}
	return nil
}

func buildRegistrationSigningPayload(reg *control.ServiceRegistration) ([]byte, error) {
	clone := proto.Clone(reg).(*control.ServiceRegistration)
	clone.OriginSignature = nil
	marshaled, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("marshaling registration signing payload: %w", err)
	}
	var buf bytes.Buffer
	buf.WriteString(ContextControlRegistration)
	buf.WriteByte(0)
	buf.Write(marshaled)
	return buf.Bytes(), nil
}

// HandlerFunc is called when a valid ServiceRegistration message is received from the mesh.
type HandlerFunc func(reg *control.ServiceRegistration)

// MeshRegistry manages the GossipSub control plane and direct registration streams.
type MeshRegistry struct {
	mu      sync.RWMutex
	host    host.Host
	ps      *pubsub.PubSub
	topic   *pubsub.Topic
	sub     *pubsub.Subscription
	handler HandlerFunc
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewMeshRegistry creates and starts a GossipSub registry on /p2p-anycast/registry/1.0.0
// and registers a direct registration stream handler on /p2p-anycast/register/1.0.0.
func NewMeshRegistry(ctx context.Context, h host.Host, handler HandlerFunc, opts ...pubsub.Option) (*MeshRegistry, error) {
	ps, err := pubsub.NewGossipSub(ctx, h, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GossipSub: %w", err)
	}

	topic, err := ps.Join(RegistryTopic)
	if err != nil {
		return nil, fmt.Errorf("failed to join registry topic %s: %w", RegistryTopic, err)
	}

	sub, err := topic.Subscribe()
	if err != nil {
		topic.Close()
		return nil, fmt.Errorf("failed to subscribe to topic %s: %w", RegistryTopic, err)
	}

	subCtx, cancel := context.WithCancel(ctx)
	reg := &MeshRegistry{
		host:    h,
		ps:      ps,
		topic:   topic,
		sub:     sub,
		handler: handler,
		ctx:     subCtx,
		cancel:  cancel,
	}

	if handler != nil {
		h.SetStreamHandler(DirectRegisterProtocolID, reg.handleDirectStream)
	}

	go reg.listenLoop()
	return reg, nil
}

func (r *MeshRegistry) ensureSigned(reg *control.ServiceRegistration) error {
	if len(reg.OriginSignature) > 0 {
		return nil
	}
	if r.host == nil {
		return nil
	}
	priv := r.host.Peerstore().PrivKey(r.host.ID())
	if priv == nil {
		return nil
	}
	return SignRegistration(reg, priv)
}

// Publish publishes a ServiceRegistration to the GossipSub mesh.
func (r *MeshRegistry) Publish(ctx context.Context, reg *control.ServiceRegistration) error {
	if reg == nil {
		return errors.New("nil service registration")
	}

	if err := r.ensureSigned(reg); err != nil {
		return err
	}

	data, err := proto.Marshal(reg)
	if err != nil {
		return fmt.Errorf("failed to marshal ServiceRegistration: %w", err)
	}

	return r.topic.Publish(ctx, data)
}

// PublishDirect sends one or more ServiceRegistration messages directly to a connected Edge peer
// over /p2p-anycast/register/1.0.0, bypassing GossipSub mesh graft delays on connect/restart.
func (r *MeshRegistry) PublishDirect(ctx context.Context, targetPeer peer.ID, regs ...*control.ServiceRegistration) error {
	if len(regs) == 0 {
		return nil
	}

	s, err := r.host.NewStream(ctx, targetPeer, DirectRegisterProtocolID)
	if err != nil {
		return fmt.Errorf("failed to open direct register stream to %s: %w", targetPeer, err)
	}
	defer s.Close()
	_ = s.SetWriteDeadline(time.Now().Add(DirectStreamReadTimeout))

	var lenBuf [4]byte
	for _, reg := range regs {
		if reg == nil {
			continue
		}
		if err := r.ensureSigned(reg); err != nil {
			return err
		}
		data, err := proto.Marshal(reg)
		if err != nil {
			return fmt.Errorf("failed to marshal ServiceRegistration: %w", err)
		}
		if len(data) > MaxRegistrationMsgSize {
			return fmt.Errorf("ServiceRegistration exceeds max size (%d > %d)", len(data), MaxRegistrationMsgSize)
		}
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
		if _, err := s.Write(lenBuf[:]); err != nil {
			s.Reset()
			return err
		}
		if _, err := s.Write(data); err != nil {
			s.Reset()
			return err
		}
	}

	return nil
}

// Close unsubscribes and closes the topic.
func (r *MeshRegistry) Close() error {
	r.cancel()
	if r.host != nil {
		r.host.RemoveStreamHandler(DirectRegisterProtocolID)
	}
	if r.sub != nil {
		r.sub.Cancel()
	}
	if r.topic != nil {
		return r.topic.Close()
	}
	return nil
}

func (r *MeshRegistry) handleDirectStream(s network.Stream) {
	defer s.Close()
	remotePeer := s.Conn().RemotePeer().String()
	localPeer := r.host.ID().String()

	var lenBuf [4]byte
	for {
		_ = s.SetReadDeadline(time.Now().Add(DirectStreamReadTimeout))
		if _, err := io.ReadFull(s, lenBuf[:]); err != nil {
			return
		}
		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		if msgLen == 0 || msgLen > MaxRegistrationMsgSize {
			s.Reset()
			return
		}
		buf := make([]byte, msgLen)
		if _, err := io.ReadFull(s, buf); err != nil {
			s.Reset()
			return
		}

		var reg control.ServiceRegistration
		if err := proto.Unmarshal(buf, &reg); err != nil {
			continue
		}

		if reg.OriginPeerId != remotePeer {
			log.Printf("[Gossip] Dropping direct registration with spoofed OriginPeerId %q from peer %s", reg.OriginPeerId, remotePeer)
			continue
		}

		if reg.TargetEdgePeerId != "" && reg.TargetEdgePeerId != localPeer {
			continue
		}

		if err := VerifyRegistration(&reg); err != nil {
			log.Printf("[Gossip] Dropping direct registration with invalid Origin signature from %s: %v", remotePeer, err)
			continue
		}

		r.mu.RLock()
		h := r.handler
		r.mu.RUnlock()

		if h != nil {
			h(&reg)
		}
	}
}

func (r *MeshRegistry) listenLoop() {
	localPeer := r.host.ID().String()
	for {
		msg, err := r.sub.Next(r.ctx)
		if err != nil {
			return // Context cancelled or subscription closed
		}

		var reg control.ServiceRegistration
		if err := proto.Unmarshal(msg.Data, &reg); err != nil {
			continue
		}

		// Cryptographically verify that the GossipSub publisher matches the claimed OriginPeerId
		if msg.GetFrom().String() != reg.OriginPeerId {
			log.Printf("[Gossip] Dropping GossipSub registration with mismatched signer %s != OriginPeerId %q",
				msg.GetFrom().String(), reg.OriginPeerId)
			continue
		}

		// Ignore registrations targeted at a different Edge router
		if reg.TargetEdgePeerId != "" && reg.TargetEdgePeerId != localPeer {
			continue
		}

		if err := VerifyRegistration(&reg); err != nil {
			log.Printf("[Gossip] Dropping GossipSub registration with invalid Origin signature from %s: %v", reg.OriginPeerId, err)
			continue
		}

		r.mu.RLock()
		h := r.handler
		r.mu.RUnlock()

		if h != nil {
			h(&reg)
		}
	}
}

