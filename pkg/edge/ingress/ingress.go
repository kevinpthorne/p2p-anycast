package ingress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"

	"p2p-anycast/pkg/control/lease"
	control "p2p-anycast/pkg/proto/control"
	"p2p-anycast/pkg/edge/forwarder"
	"p2p-anycast/pkg/edge/proxy"
	"p2p-anycast/pkg/edge/sni"
)

var (
	ErrNoOriginAvailable = errors.New("no active origin available for service")
	ErrPortConflict      = errors.New("port already bound with conflicting policy")
)

// Router orchestrates dynamic public listeners, policy routing, and proxying on the Edge.
type Router struct {
	mu           sync.RWMutex
	host         host.Host
	leaseMgr     *lease.Manager
	forwarder    *forwarder.EdgeDatagramForwarder
	tcpListeners map[uint32]net.Listener
	udpListeners map[uint32]*net.UDPConn
	pingCache    map[peer.ID]time.Duration
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewRouter initializes the Edge ingress router.
func NewRouter(ctx context.Context, h host.Host, leaseMgr *lease.Manager) *Router {
	rCtx, cancel := context.WithCancel(ctx)
	r := &Router{
		host:         h,
		leaseMgr:     leaseMgr,
		forwarder:    forwarder.NewEdgeDatagramForwarder(rCtx, h),
		tcpListeners: make(map[uint32]net.Listener),
		udpListeners: make(map[uint32]*net.UDPConn),
		pingCache:    make(map[peer.ID]time.Duration),
		ctx:          rCtx,
		cancel:       cancel,
	}

	// Register network notifier to evict peer immediately on disconnect
	h.Network().Notify(&network.NotifyBundle{
		DisconnectedF: func(net network.Network, conn network.Conn) {
			pID := conn.RemotePeer()
			if len(net.ConnsToPeer(pID)) == 0 {
				r.HandlePeerDisconnected(pID)
			}
		},
		ConnectedF: func(net network.Network, conn network.Conn) {
			r.forwarder.StartDatagramReceiver(conn)
		},
	})

	return r
}

// Close stops all listeners and forwarders.
func (r *Router) Close() {
	r.cancel()
	r.forwarder.Close()

	r.mu.Lock()
	defer r.mu.Unlock()

	for port, ln := range r.tcpListeners {
		ln.Close()
		delete(r.tcpListeners, port)
	}
	for port, uln := range r.udpListeners {
		uln.Close()
		delete(r.udpListeners, port)
	}
}

// HandlePeerDisconnected cleans up all registrations for a disconnected peer and stops listeners if empty.
func (r *Router) HandlePeerDisconnected(pID peer.ID) {
	evicted := r.leaseMgr.EvictPeer(pID.String())
	for _, reg := range evicted {
		r.SyncPortListener(reg.PublicPort)
	}
}

// SyncPortListener ensures the appropriate OS socket listeners are open or closed based on active leases.
func (r *Router) SyncPortListener(port uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	regs := r.leaseMgr.GetRegistrationsForPort(port)
	hasTCP := false
	hasUDP := false

	for _, reg := range regs {
		switch reg.Protocol {
		case control.TransportProtocol_TCP:
			hasTCP = true
		case control.TransportProtocol_UDP:
			hasUDP = true
		case control.TransportProtocol_TCP_AND_UDP:
			hasTCP = true
			hasUDP = true
		}
	}

	// Synchronize TCP listener
	if hasTCP {
		if _, exists := r.tcpListeners[port]; !exists {
			ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
			if err == nil {
				r.tcpListeners[port] = ln
				go r.acceptTCP(port, ln)
			}
		}
	} else {
		if ln, exists := r.tcpListeners[port]; exists {
			ln.Close()
			delete(r.tcpListeners, port)
		}
	}

	// Synchronize UDP listener
	if hasUDP {
		if _, exists := r.udpListeners[port]; !exists {
			addr := &net.UDPAddr{IP: net.IPv4zero, Port: int(port)}
			uln, err := net.ListenUDP("udp", addr)
			if err == nil {
				r.udpListeners[port] = uln
				go r.acceptUDP(port, uln)
			}
		}
	} else {
		if uln, exists := r.udpListeners[port]; exists {
			uln.Close()
			delete(r.udpListeners, port)
		}
	}
}

// acceptTCP handles incoming client connections on a public TCP port.
func (r *Router) acceptTCP(port uint32, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // Listener closed
		}

		go r.handleTCPConn(port, conn)
	}
}

func (r *Router) handleTCPConn(port uint32, clientConn net.Conn) {
	regs := r.leaseMgr.GetRegistrationsForPort(port)
	if len(regs) == 0 {
		clientConn.Close()
		return
	}

	policy := regs[0].Policy
	var selectedReg *control.ServiceRegistration
	var peekedBytes []byte

	switch policy {
	case control.RoutingPolicy_TLS_SNI:
		// Read initial bytes to peek SNI
		buf := make([]byte, 4096)
		_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := clientConn.Read(buf)
		_ = clientConn.SetReadDeadline(time.Time{})
		if err != nil {
			resetTCP(clientConn)
			return
		}
		peekedBytes = buf[:n]

		sniHost, err := sni.ExtractSNI(peekedBytes)
		if err != nil {
			resetTCP(clientConn)
			return
		}

		// Find registration matching SNI
		for _, reg := range regs {
			if reg.SniHostname == sniHost {
				selectedReg = reg
				break
			}
		}

		if selectedReg == nil {
			resetTCP(clientConn)
			return
		}

	case control.RoutingPolicy_CLUSTERED_RTT:
		selectedReg = r.selectLowestRTT(regs)

	case control.RoutingPolicy_FAILOVER_STANDBY, control.RoutingPolicy_STRICT_SINGLETON:
		selectedReg = regs[0]
	}

	if selectedReg == nil {
		resetTCP(clientConn)
		return
	}

	originPeer, err := peer.Decode(selectedReg.OriginPeerId)
	if err != nil {
		resetTCP(clientConn)
		return
	}

	// Open libp2p stream to target Origin
	streamCtx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
	defer cancel()

	s, err := r.host.NewStream(streamCtx, originPeer, proxy.TCPProtocolID)
	if err != nil {
		resetTCP(clientConn)
		return
	}

	var bindingID [16]byte
	copy(bindingID[:], selectedReg.BindingId)
	var hmacToken [16]byte
	copy(hmacToken[:], selectedReg.OriginHmacCapability)

	_ = proxy.PipeTCPStream(clientConn, s, bindingID, hmacToken, selectedReg.EnableProxyProtocol, peekedBytes)
}

func resetTCP(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = conn.Close()
}

// acceptUDP reads incoming UDP packets on a public port and routes them over QUIC datagrams.
func (r *Router) acceptUDP(port uint32, uln *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := uln.ReadFromUDP(buf)
		if err != nil {
			return // Listener closed
		}

		regs := r.leaseMgr.GetRegistrationsForPort(port)
		if len(regs) == 0 {
			continue // Drop packet
		}

		reg := regs[0]
		if reg.Policy == control.RoutingPolicy_CLUSTERED_RTT {
			reg = r.selectLowestRTT(regs)
		}

		originPeer, err := peer.Decode(reg.OriginPeerId)
		if err != nil {
			continue
		}

		// Strictly drop if peer is disconnected
		if len(r.host.Network().ConnsToPeer(originPeer)) == 0 {
			if reg.Policy == control.RoutingPolicy_STRICT_SINGLETON {
				// Immediate fail-closed: unbind and drop
				go r.SyncPortListener(port)
			}
			continue
		}

		var bindingID [16]byte
		copy(bindingID[:], reg.BindingId)
		var hmacToken [16]byte
		copy(hmacToken[:], reg.OriginHmacCapability)

		packetData := make([]byte, n)
		copy(packetData, buf[:n])

		_ = r.forwarder.ForwardPacket(originPeer, bindingID, hmacToken, clientAddr, uln, packetData)
	}
}

// selectLowestRTT picks the origin with the lowest RTT using libp2p Ping.
func (r *Router) selectLowestRTT(candidates []*control.ServiceRegistration) *control.ServiceRegistration {
	if len(candidates) == 1 {
		return candidates[0]
	}

	var bestReg *control.ServiceRegistration
	bestRTT := time.Duration(1<<63 - 1)

	for _, reg := range candidates {
		pID, err := peer.Decode(reg.OriginPeerId)
		if err != nil {
			continue
		}

		r.mu.RLock()
		cachedRTT, exists := r.pingCache[pID]
		r.mu.RUnlock()

		if !exists {
			// Measure RTT with timeout
			ctx, cancel := context.WithTimeout(r.ctx, 500*time.Millisecond)
			resChan := ping.Ping(ctx, r.host, pID)
			select {
			case res := <-resChan:
				cancel()
				if res.Error == nil {
					cachedRTT = res.RTT
					r.mu.Lock()
					r.pingCache[pID] = cachedRTT
					r.mu.Unlock()
				} else {
					cachedRTT = 10 * time.Second
				}
			case <-ctx.Done():
				cancel()
				cachedRTT = 10 * time.Second
			}
		}

		if cachedRTT < bestRTT {
			bestRTT = cachedRTT
			bestReg = reg
		}
	}

	if bestReg == nil {
		return candidates[0]
	}
	return bestReg
}
