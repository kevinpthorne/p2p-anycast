package gossip

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
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
)

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

// Publish publishes a ServiceRegistration to the GossipSub mesh.
func (r *MeshRegistry) Publish(ctx context.Context, reg *control.ServiceRegistration) error {
	if reg == nil {
		return errors.New("nil service registration")
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

	var lenBuf [4]byte
	for _, reg := range regs {
		if reg == nil {
			continue
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

	var lenBuf [4]byte
	for {
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

		r.mu.RLock()
		h := r.handler
		r.mu.RUnlock()

		if h != nil {
			h(&reg)
		}
	}
}

func (r *MeshRegistry) listenLoop() {
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

		r.mu.RLock()
		h := r.handler
		r.mu.RUnlock()

		if h != nil {
			h(&reg)
		}
	}
}
