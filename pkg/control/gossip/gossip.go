package gossip

import (
	"context"
	"errors"
	"fmt"
	"sync"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"google.golang.org/protobuf/proto"

	control "p2p-anycast/pkg/proto/control"
)

const (
	// RegistryTopic is the GossipSub topic for service registration and routing announcements.
	RegistryTopic = "/p2p-anycast/registry/1.0.0"
)

// HandlerFunc is called when a valid ServiceRegistration message is received from the mesh.
type HandlerFunc func(reg *control.ServiceRegistration)

// MeshRegistry manages the GossipSub control plane.
type MeshRegistry struct {
	mu         sync.RWMutex
	ps         *pubsub.PubSub
	topic      *pubsub.Topic
	sub        *pubsub.Subscription
	handler    HandlerFunc
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewMeshRegistry creates and starts a GossipSub registry on /p2p-anycast/registry/1.0.0.
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
		ps:      ps,
		topic:   topic,
		sub:     sub,
		handler: handler,
		ctx:     subCtx,
		cancel:  cancel,
	}

	go reg.listenLoop()
	return reg, nil
}

// Publish publishes a ServiceRegistration to the mesh.
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

// Close unsubscribes and closes the topic.
func (r *MeshRegistry) Close() error {
	r.cancel()
	if r.sub != nil {
		r.sub.Cancel()
	}
	if r.topic != nil {
		return r.topic.Close()
	}
	return nil
}

func (r *MeshRegistry) listenLoop() {
	for {
		msg, err := r.sub.Next(r.ctx)
		if err != nil {
			return // Context cancelled or subscription closed
		}

		// Avoid self-reflection if desired, but in libp2p GossipSub local origin messages can be processed
		var reg control.ServiceRegistration
		if err := proto.Unmarshal(msg.Data, &reg); err != nil {
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
