package dialer

import (
	"context"
	"fmt"
	"log"
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
		leaseEpoch:    uint64(time.Now().UnixMilli()),
		ctx:           oCtx,
		cancel:        cancel,
	}

	if cfg.NATTable != nil && cfg.Authenticator != nil {
		cfg.NATTable.SetAuthenticator(cfg.Authenticator)
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
			pID := conn.RemotePeer()
			if len(net.ConnsToPeer(pID)) == 0 {
				node.mu.Lock()
				delete(node.activeEdges, pID)
				node.mu.Unlock()
			}
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

// UpdateServices updates the active services list, prunes removed dispatch routes,
// revokes removed services on connected edges, and announces the current services.
func (o *OriginNode) UpdateServices(services []ServiceConfig) {
	o.mu.Lock()
	oldServices := o.services
	o.services = services
	o.leaseEpoch++
	active := make([]peer.ID, 0, len(o.activeEdges))
	for pID := range o.activeEdges {
		active = append(active, pID)
	}
	o.mu.Unlock()

	newBindings := make(map[[16]byte]bool, len(services))
	for _, svc := range services {
		bID := binding.DeriveBindingID(svc.ServiceID, svc.Protocol, svc.PublicPort, svc.SNIHostname)
		newBindings[bID] = true
		o.routes.AddRoute(dispatch.Route{
			BindingID:  bID,
			Target:     svc.Target,
			Protocol:   svc.Protocol,
			PublicPort: svc.PublicPort,
			ServiceID:  svc.ServiceID,
		})
	}

	var removed []ServiceConfig
	for _, oldSvc := range oldServices {
		bID := binding.DeriveBindingID(oldSvc.ServiceID, oldSvc.Protocol, oldSvc.PublicPort, oldSvc.SNIHostname)
		if !newBindings[bID] {
			o.routes.RemoveRoute(bID)
			removed = append(removed, oldSvc)
		}
	}

	for _, edgePeer := range active {
		if len(removed) > 0 {
			o.revokeServicesOnEdge(edgePeer, removed)
		}
		o.announceServicesToEdge(edgePeer)
	}
}

func (o *OriginNode) revokeServicesOnEdge(edgePeer peer.ID, removed []ServiceConfig) {
	originPeerID := o.host.ID().String()
	now := time.Now().Unix()
	regs := make([]*control.ServiceRegistration, 0, len(removed))
	for _, svc := range removed {
		bID := binding.DeriveBindingID(svc.ServiceID, svc.Protocol, svc.PublicPort, svc.SNIHostname)
		regs = append(regs, &control.ServiceRegistration{
			Type:             control.MessageType_REVOKE,
			BindingId:        bID[:],
			ServiceId:        svc.ServiceID,
			OriginPeerId:     originPeerID,
			Protocol:         svc.Protocol,
			PublicPort:       svc.PublicPort,
			Policy:           svc.Policy,
			SniHostname:      svc.SNIHostname,
			TargetEdgePeerId: edgePeer.String(),
			Timestamp:        now,
		})
	}

	go func() {
		revCtx, cancel := context.WithTimeout(o.ctx, 5*time.Second)
		_ = o.registry.PublishDirect(revCtx, edgePeer, regs...)
		cancel()
		for _, reg := range regs {
			_ = o.registry.Publish(o.ctx, reg)
		}
	}()
}

// maintainConnection persists an outbound QUIC connection to an Edge with exponential backoff.
func (o *OriginNode) maintainConnection(addr multiaddr.Multiaddr) {
	addrInfo, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		log.Printf("[Origin] Invalid edge multiaddr %s: %v", addr, err)
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
		if err != nil {
			log.Printf("[Origin] Failed to connect to edge %s (%s): %v", addrInfo.ID, addr, err)
		} else {
			// Run mutual authentication over /p2p-anycast/auth/1.0.0
			claims, authErr := o.authenticator.AuthenticateOutbound(o.ctx, addrInfo.ID)
			if authErr != nil {
				log.Printf("[Origin] Mutual authentication failed with edge %s: %v", addrInfo.ID, authErr)
			} else {
				log.Printf("[Origin] Successfully connected and authenticated with edge %s (Subject: %q)", addrInfo.ID, claims.SubjectId)
				o.mu.Lock()
				o.activeEdges[addrInfo.ID] = true
				o.mu.Unlock()

				// Announce services to Edge
				o.announceServicesToEdge(addrInfo.ID)

				backoff = 500 * time.Millisecond

				// Wait until connection closes
				for {
					if len(o.host.Network().ConnsToPeer(addrInfo.ID)) == 0 {
						log.Printf("[Origin] Connection to edge %s lost, will reconnect...", addrInfo.ID)
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

func (o *OriginNode) buildServiceRegistrations(edgePeer peer.ID, msgType control.MessageType) []*control.ServiceRegistration {
	o.mu.RLock()
	svcs := make([]ServiceConfig, len(o.services))
	copy(svcs, o.services)
	epoch := o.leaseEpoch
	o.mu.RUnlock()

	originPeerID := o.host.ID().String()
	edgePeerStr := edgePeer.String()
	now := time.Now().Unix()
	regs := make([]*control.ServiceRegistration, 0, len(svcs))

	for _, svc := range svcs {
		bID := binding.DeriveBindingID(svc.ServiceID, svc.Protocol, svc.PublicPort, svc.SNIHostname)
		// Scope capability token strictly to the target Edge's Peer ID so no other peer can replay it
		token := binding.GenerateHMAC(o.originKey, edgePeerStr, svc.PublicPort, bID)

		demuxMode := control.DemuxMode_DEMUX_PORT
		if svc.SNIHostname != "" {
			demuxMode = control.DemuxMode_DEMUX_TLS_SNI
		}

		regs = append(regs, &control.ServiceRegistration{
			Type:                 msgType,
			BindingId:            bID[:],
			ServiceId:            svc.ServiceID,
			OriginPeerId:         originPeerID,
			Protocol:             svc.Protocol,
			PublicPort:           svc.PublicPort,
			Policy:               svc.Policy,
			SniHostname:          svc.SNIHostname,
			DemuxMode:            demuxMode,
			LeaseDurationSec:     60,
			LeaseEpoch:           epoch,
			EnableProxyProtocol:  svc.EnableProxyProtocol,
			OriginHmacCapability: token[:],
			TargetEdgePeerId:     edgePeerStr,
			Timestamp:            now,
		})
	}

	return regs
}

func (o *OriginNode) announceServicesToEdge(edgePeer peer.ID) {
	go func() {
		regs := o.buildServiceRegistrations(edgePeer, control.MessageType_ANNOUNCE)
		if len(regs) == 0 {
			return
		}

		log.Printf("[Origin] Announcing %d service(s) to edge %s...", len(regs), edgePeer)

		// 1. Immediate deterministic point-to-point sync over /p2p-anycast/register/1.0.0
		syncCtx, cancel := context.WithTimeout(o.ctx, 5*time.Second)
		if err := o.registry.PublishDirect(syncCtx, edgePeer, regs...); err != nil {
			log.Printf("[Origin] Direct registration push to edge %s failed (falling back to GossipSub): %v", edgePeer, err)
		}
		cancel()

		// 2. Also publish to GossipSub mesh (with TargetEdgePeerId set) so multi-hop mesh peers deliver to target Edge
		for attempt := 1; attempt <= 2; attempt++ {
			time.Sleep(time.Duration(attempt*150) * time.Millisecond)
			for _, reg := range regs {
				if err := o.registry.Publish(o.ctx, reg); err != nil {
					log.Printf("[Origin] Failed to publish announcement for %s to mesh: %v", reg.ServiceId, err)
				}
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

	if len(active) == 0 {
		return
	}

	for _, edgePeer := range active {
		regs := o.buildServiceRegistrations(edgePeer, control.MessageType_HEARTBEAT)
		if len(regs) == 0 {
			continue
		}

		for _, reg := range regs {
			_ = o.registry.Publish(o.ctx, reg)
		}

		hbCtx, cancel := context.WithTimeout(o.ctx, 3*time.Second)
		_ = o.registry.PublishDirect(hbCtx, edgePeer, regs...)
		cancel()
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
				if err := o.natTable.HandleForwardDatagram(edgePeer, data); err != nil {
					log.Printf("[Origin] Failed to handle UDP forward datagram from %s: %v", edgePeer, err)
				}
			}
		}
	}()
}
