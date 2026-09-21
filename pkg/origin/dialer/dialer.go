package dialer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"p2p-anycast/pkg/control/binding"
	"p2p-anycast/pkg/control/gossip"
	control "p2p-anycast/pkg/proto/control"
	"p2p-anycast/pkg/origin/dispatch"
	"p2p-anycast/pkg/origin/nat"
	"p2p-anycast/pkg/transport/auth"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

// ServiceConfig defines an announced service on the Origin.
type ServiceConfig struct {
	ServiceID           string
	Protocol            control.TransportProtocol
	PublicPort          uint32
	Policy              control.RoutingPolicy
	SNIHostname         string
	Target              string // e.g. "127.0.0.1:5060" or "minecraft.minecraft.svc.cluster.local:25565"
	EnableProxyProtocol bool
}

// OriginNode manages outbound persistent connections to Edges and heartbeat announcements.
type OriginNode struct {
	mu           sync.RWMutex
	host         host.Host
	authenticator *auth.Authenticator
	registry     *gossip.MeshRegistry
	routes       *dispatch.Table
	natTable     *nat.Table
	originKey    []byte
	edgeAddrs    []multiaddr.Multiaddr
	services     []ServiceConfig
	activeEdges  map[peer.ID]bool
	leaseEpoch   uint64
	ctx          context.Context
	cancel       context.CancelFunc
}

// Config defines OriginNode options.
type Config struct {
	Host          host.Host
	Authenticator *auth.Authenticator
	Registry      *gossip.MeshRegistry
	Routes        *dispatch.Table
	NATTable      *nat.Table
	OriginKey     []byte
	EdgeAddrs     []string
	Services      []ServiceConfig
}

// NewOriginNode creates a new Origin daemon instance.
func NewOriginNode(ctx context.Context, cfg Config) (*OriginNode, error) {
	oCtx, cancel := context.WithCancel(ctx)

	var mAddrs []multiaddr.Multiaddr
	for _, a := range cfg.EdgeAddrs {
		ma, err := multiaddr.NewMultiaddr(a)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("invalid edge multiaddr %s: %w", a, err)
		}
		mAddrs = append(mAddrs, ma)
	}

	node := &OriginNode{
		host:          cfg.Host,
		authenticator: cfg.Authenticator,
		registry:      cfg.Registry,
		routes:        cfg.Routes,
		natTable:      cfg.NATTable,
		originKey:     cfg.OriginKey,
		edgeAddrs:     mAddrs,
		services:      cfg.Services,
		activeEdges:   make(map[peer.ID]bool),
		leaseEpoch:    uint64(time.Now().Unix()),
		ctx:           oCtx,
		cancel:        cancel,
	}

	// Register routes in dispatch table
	for _, svc := range cfg.Services {
		bID := binding.DeriveBindingID(svc.ServiceID, svc.Protocol, svc.PublicPort, svc.SNIHostname)
		cfg.Routes.AddRoute(dispatch.Route{
			BindingID:  bID,
			Target:     svc.Target,
			Protocol:   svc.Protocol,
			PublicPort: svc.PublicPort,
			ServiceID:  svc.ServiceID,
		})
	}

	// Register connection watcher to listen for UDP datagrams from connected edges
	cfg.Host.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(net network.Network, conn network.Conn) {
			node.startEdgeDatagramReceiver(conn)
		},
		DisconnectedF: func(net network.Network, conn network.Conn) {
			node.mu.Lock()
			delete(node.activeEdges, conn.RemotePeer())
			node.mu.Unlock()
		},
	})

	return node, nil
}

// Start launches the outbound dialer loops and heartbeat publisher.
func (o *OriginNode) Start() {
	for _, maddr := range o.edgeAddrs {
		go o.maintainConnection(maddr)
	}

	go o.heartbeatLoop()
}

// Close stops the origin node.
func (o *OriginNode) Close() {
	o.cancel()
}

// maintainConnection persists an outbound QUIC connection to an Edge with exponential backoff.
func (o *OriginNode) maintainConnection(addr multiaddr.Multiaddr) {
	addrInfo, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		return
	}

	backoff := 500 * time.Millisecond
	maxBackoff := 15 * time.Second

	for {
		select {
		case <-o.ctx.Done():
			return
		default:
		}

		err := o.host.Connect(o.ctx, *addrInfo)
		if err == nil {
			// Run mutual authentication over /p2p-anycast/auth/1.0.0
			_, authErr := o.authenticator.AuthenticateOutbound(o.ctx, addrInfo.ID)
			if authErr == nil {
				o.mu.Lock()
				o.activeEdges[addrInfo.ID] = true
				o.mu.Unlock()

				// Announce services to Edge
				o.announceServicesToEdge(addrInfo.ID)

				backoff = 500 * time.Millisecond

				// Wait until connection closes
				for {
					if len(o.host.Network().ConnsToPeer(addrInfo.ID)) == 0 {
						break
					}
					select {
					case <-o.ctx.Done():
						return
					case <-time.After(1 * time.Second):
					}
				}
			}
		}

		select {
		case <-o.ctx.Done():
			return
		case <-time.After(backoff):
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func (o *OriginNode) announceServicesToEdge(edgePeer peer.ID) {
	go func() {
		// Pubsub protocol negotiation happens asynchronously after Connect()
		// Announce immediately and retry after a brief delay so pubsub mesh is formed
		for attempt := 1; attempt <= 4; attempt++ {
			time.Sleep(time.Duration(attempt*100) * time.Millisecond)
			for _, svc := range o.services {
				bID := binding.DeriveBindingID(svc.ServiceID, svc.Protocol, svc.PublicPort, svc.SNIHostname)
				token := binding.GenerateHMAC(o.originKey, edgePeer.String(), svc.PublicPort, bID)

				reg := &control.ServiceRegistration{
					Type:                 control.MessageType_ANNOUNCE,
					BindingId:            bID[:],
					ServiceId:            svc.ServiceID,
					OriginPeerId:         o.host.ID().String(),
					Protocol:             svc.Protocol,
					PublicPort:           svc.PublicPort,
					Policy:               svc.Policy,
					SniHostname:          svc.SNIHostname,
					LeaseDurationSec:     60,
					LeaseEpoch:           o.leaseEpoch,
					EnableProxyProtocol:  svc.EnableProxyProtocol,
					OriginHmacCapability: token[:],
				}

				_ = o.registry.Publish(o.ctx, reg)
			}
		}
	}()
}

func (o *OriginNode) heartbeatLoop() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-o.ctx.Done():
			return
		case <-ticker.C:
			o.publishHeartbeats()
		}
	}
}

func (o *OriginNode) publishHeartbeats() {
	o.mu.RLock()
	active := make([]peer.ID, 0, len(o.activeEdges))
	for pID := range o.activeEdges {
		active = append(active, pID)
	}
	o.mu.RUnlock()

	for _, edgePeer := range active {
		for _, svc := range o.services {
			bID := binding.DeriveBindingID(svc.ServiceID, svc.Protocol, svc.PublicPort, svc.SNIHostname)
			token := binding.GenerateHMAC(o.originKey, edgePeer.String(), svc.PublicPort, bID)

			reg := &control.ServiceRegistration{
				Type:                 control.MessageType_HEARTBEAT,
				BindingId:            bID[:],
				ServiceId:            svc.ServiceID,
				OriginPeerId:         o.host.ID().String(),
				Protocol:             svc.Protocol,
				PublicPort:           svc.PublicPort,
				Policy:               svc.Policy,
				SniHostname:          svc.SNIHostname,
				LeaseDurationSec:     60,
				LeaseEpoch:           o.leaseEpoch,
				EnableProxyProtocol:  svc.EnableProxyProtocol,
				OriginHmacCapability: token[:],
			}

			_ = o.registry.Publish(o.ctx, reg)
		}
	}
}

func (o *OriginNode) startEdgeDatagramReceiver(conn network.Conn) {
	edgePeer := conn.RemotePeer()
	go func() {
		for {
			select {
			case <-o.ctx.Done():
				return
			default:
			}

			data, err := p2pquic.ReceiveDatagram(o.ctx, conn)
			if err != nil {
				return
			}

			if o.natTable != nil {
				_ = o.natTable.HandleForwardDatagram(edgePeer, data)
			}
		}
	}()
}
