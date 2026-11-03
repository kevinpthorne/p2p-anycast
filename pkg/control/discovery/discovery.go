package discovery

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/multiformats/go-multiaddr"
)

const (
	// EdgeRendezvousNamespace is the content routing rendezvous topic for edge discovery.
	EdgeRendezvousNamespace = "p2p-anycast:edges:v1"

	// DHTProtocolPrefix isolates our Kademlia DHT from the public IPFS DHT.
	DHTProtocolPrefix = protocol.ID("/p2p-anycast/dht")

	// DefaultAdvertiseInterval is the interval at which edge routers re-advertise their presence.
	DefaultAdvertiseInterval = 10 * time.Minute

	// DefaultDiscoveryInterval is the polling interval for origins discovering edge routers.
	DefaultDiscoveryInterval = 30 * time.Second

	// DefaultAdvertiseTTL is the provider record TTL.
	DefaultAdvertiseTTL = 1 * time.Hour
)

// AdvertiserOption configures an EdgeAdvertiser.
type AdvertiserOption func(*EdgeAdvertiser)

// WithAdvertiseInterval overrides the default advertisement interval.
func WithAdvertiseInterval(d time.Duration) AdvertiserOption {
	return func(a *EdgeAdvertiser) {
		if d > 0 {
			a.advertiseInterval = d
		}
	}
}

// WithAdvertiseTTL overrides the default provider record TTL.
func WithAdvertiseTTL(ttl time.Duration) AdvertiserOption {
	return func(a *EdgeAdvertiser) {
		if ttl > 0 {
			a.advertiseTTL = ttl
		}
	}
}

// EdgeAdvertiser advertises the presence of an edge router on the isolated DHT.
type EdgeAdvertiser struct {
	host              host.Host
	dht               *dht.IpfsDHT
	routing           *drouting.RoutingDiscovery
	advertiseInterval time.Duration
	advertiseTTL      time.Duration
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
}

// NewEdgeAdvertiser creates an EdgeAdvertiser running in DHT Server mode.
func NewEdgeAdvertiser(ctx context.Context, h host.Host, bootstrapAddrs []multiaddr.Multiaddr, opts ...AdvertiserOption) (*EdgeAdvertiser, error) {
	advCtx, cancel := context.WithCancel(ctx)

	kadDHT, err := dht.New(
		advCtx,
		h,
		dht.Mode(dht.ModeServer),
		dht.ProtocolPrefix(DHTProtocolPrefix),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create DHT in server mode: %w", err)
	}

	a := &EdgeAdvertiser{
		host:              h,
		dht:               kadDHT,
		routing:           drouting.NewRoutingDiscovery(kadDHT),
		advertiseInterval: DefaultAdvertiseInterval,
		advertiseTTL:      DefaultAdvertiseTTL,
		ctx:               advCtx,
		cancel:            cancel,
	}

	for _, opt := range opts {
		opt(a)
	}

	// Connect to bootstrap peers if provided.
	if len(bootstrapAddrs) > 0 {
		peerInfos, err := peer.AddrInfosFromP2pAddrs(bootstrapAddrs...)
		if err != nil {
			log.Printf("[discovery] Warning: failed to parse some bootstrap addrs: %v", err)
		}
		for _, pi := range peerInfos {
			if pi.ID == h.ID() {
				continue
			}
			h.Peerstore().AddAddrs(pi.ID, pi.Addrs, peerstore.PermanentAddrTTL)
			if err := h.Connect(advCtx, pi); err != nil {
				log.Printf("[discovery] Warning: failed to connect to bootstrap peer %s: %v", pi.ID, err)
			}
		}
	}

	if err := kadDHT.Bootstrap(advCtx); err != nil {
		cancel()
		_ = kadDHT.Close()
		return nil, fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	a.wg.Add(1)
	go a.advertiseLoop()

	return a, nil
}

// DHT returns the underlying IpfsDHT instance.
func (a *EdgeAdvertiser) DHT() *dht.IpfsDHT {
	return a.dht
}

func (a *EdgeAdvertiser) advertiseLoop() {
	defer a.wg.Done()

	// Initial advertise with fast retry until routing table has peers or context cancels
	for {
		_, err := a.routing.Advertise(a.ctx, EdgeRendezvousNamespace, discovery.TTL(a.advertiseTTL))
		if err == nil {
			break
		}
		select {
		case <-a.ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}

	ticker := time.NewTicker(a.advertiseInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			if _, err := a.routing.Advertise(a.ctx, EdgeRendezvousNamespace, discovery.TTL(a.advertiseTTL)); err != nil {
				if a.ctx.Err() == nil {
					log.Printf("[discovery] Periodic advertisement failed: %v", err)
				}
			}
		}
	}
}

// Close stops advertising and shuts down the DHT.
func (a *EdgeAdvertiser) Close() error {
	a.cancel()
	a.wg.Wait()
	return a.dht.Close()
}

// DiscovererOption configures an EdgeDiscoverer.
type DiscovererOption func(*EdgeDiscoverer)

// EdgeDiscoverer queries the isolated DHT for advertised edge routers.
type EdgeDiscoverer struct {
	host    host.Host
	dht     *dht.IpfsDHT
	routing *drouting.RoutingDiscovery
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewEdgeDiscoverer creates an EdgeDiscoverer running in DHT Client mode.
func NewEdgeDiscoverer(ctx context.Context, h host.Host, opts ...DiscovererOption) (*EdgeDiscoverer, error) {
	discCtx, cancel := context.WithCancel(ctx)

	kadDHT, err := dht.New(
		discCtx,
		h,
		dht.Mode(dht.ModeClient),
		dht.ProtocolPrefix(DHTProtocolPrefix),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create DHT in client mode: %w", err)
	}

	d := &EdgeDiscoverer{
		host:    h,
		dht:     kadDHT,
		routing: drouting.NewRoutingDiscovery(kadDHT),
		ctx:     discCtx,
		cancel:  cancel,
	}

	for _, opt := range opts {
		opt(d)
	}

	return d, nil
}

// DHT returns the underlying IpfsDHT instance.
func (d *EdgeDiscoverer) DHT() *dht.IpfsDHT {
	return d.dht
}

// Bootstrap connects to bootstrap peers and initializes the client DHT routing table.
func (d *EdgeDiscoverer) Bootstrap(ctx context.Context, peers []peer.AddrInfo) error {
	for _, p := range peers {
		if p.ID == d.host.ID() {
			continue
		}
		d.host.Peerstore().AddAddrs(p.ID, p.Addrs, peerstore.PermanentAddrTTL)
		if err := d.host.Connect(ctx, p); err != nil {
			log.Printf("[discovery] Warning: failed to connect to bootstrap peer %s: %v", p.ID, err)
		}
	}

	return d.dht.Bootstrap(ctx)
}

// FindEdges queries the DHT for advertised edge routers under EdgeRendezvousNamespace.
func (d *EdgeDiscoverer) FindEdges(ctx context.Context, limit int) (<-chan peer.AddrInfo, error) {
	var opts []discovery.Option
	if limit > 0 {
		opts = append(opts, discovery.Limit(limit))
	}
	return d.routing.FindPeers(ctx, EdgeRendezvousNamespace, opts...)
}

// Close shuts down the discoverer and DHT client.
func (d *EdgeDiscoverer) Close() error {
	d.cancel()
	return d.dht.Close()
}
