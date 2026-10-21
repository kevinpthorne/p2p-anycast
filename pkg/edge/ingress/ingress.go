package ingress

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"

	"p2p-anycast/pkg/control/lease"
	"p2p-anycast/pkg/edge/firewall"
	"p2p-anycast/pkg/edge/forwarder"
	"p2p-anycast/pkg/edge/proxy"
	"p2p-anycast/pkg/edge/sni"
	control "p2p-anycast/pkg/proto/control"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

const (
	// PingCacheTTL is the maximum age of a cached peer RTT before an asynchronous refresh is triggered.
	PingCacheTTL = 30 * time.Second
)

var (
	ErrNoOriginAvailable = errors.New("no active origin available for service")
	ErrPortConflict      = errors.New("port already bound with conflicting policy")
	ErrReservedPort      = errors.New("public port is reserved for administrative or mesh transport use")
)

type pingEntry struct {
	rtt        time.Duration
	measuredAt time.Time
	refreshing bool
}

// Router orchestrates dynamic public listeners, policy routing, and proxying on the Edge.
type Router struct {
	mu            sync.RWMutex
	host          host.Host
	leaseMgr      *lease.Manager
	forwarder     *forwarder.EdgeDatagramForwarder
	firewall      firewall.Manager
	reservedPorts map[uint32]bool
	tcpListeners  map[uint32]net.Listener
	udpListeners  map[uint32]*net.UDPConn
	pingCache     map[peer.ID]pingEntry
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewRouter initializes the Edge ingress router with an optional firewall manager.
func NewRouter(ctx context.Context, h host.Host, leaseMgr *lease.Manager, fw firewall.Manager) *Router {
	if fw == nil {
		fw = firewall.NewNoopManager()
	}

	reserved := map[uint32]bool{
		0:  true,
		22: true, // SSH management port protection
	}
	if h != nil {
		for _, ma := range h.Addrs() {
			parts := strings.Split(ma.String(), "/")
			for i := 0; i+1 < len(parts); i++ {
				if parts[i] == "udp" || parts[i] == "tcp" {
					if p, err := strconv.ParseUint(parts[i+1], 10, 32); err == nil && p > 0 {
						reserved[uint32(p)] = true
					}
				}
			}
		}
	}

	rCtx, cancel := context.WithCancel(ctx)
	r := &Router{
		host:          h,
		leaseMgr:      leaseMgr,
		forwarder:     forwarder.NewEdgeDatagramForwarder(rCtx, h),
		firewall:      fw,
		reservedPorts: reserved,
		tcpListeners:  make(map[uint32]net.Listener),
		udpListeners:  make(map[uint32]*net.UDPConn),
		pingCache:     make(map[peer.ID]pingEntry),
		ctx:           rCtx,
		cancel:        cancel,
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

// IsReservedPort reports whether a public port is reserved on this Edge router.
func (r *Router) IsReservedPort(port uint32) bool {
	if port == 0 || port > 65535 {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.reservedPorts[port]
}

// AddReservedPort marks a port as reserved so Origins cannot dynamically bind it.
func (r *Router) AddReservedPort(port uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reservedPorts[port] = true
}

// Close stops all listeners, forwarders, and cleans up firewall rules.
func (r *Router) Close() {
	r.cancel()
	r.forwarder.Close()

	r.mu.Lock()
	for port, ln := range r.tcpListeners {
		ln.Close()
		delete(r.tcpListeners, port)
	}
	for port, uln := range r.udpListeners {
		uln.Close()
		delete(r.udpListeners, port)
	}
	r.mu.Unlock()

	_ = r.firewall.Close()
}

// HandlePeerDisconnected cleans up all registrations for a disconnected peer and stops listeners if empty.
func (r *Router) HandlePeerDisconnected(pID peer.ID) {
	r.mu.Lock()
	delete(r.pingCache, pID)
	r.mu.Unlock()

	evicted := r.leaseMgr.EvictPeer(pID.String())
	for _, reg := range evicted {
		r.SyncPortListener(reg.PublicPort)
	}
}

// SyncPortListener ensures the appropriate OS socket listeners are open or closed based on active leases,
// and synchronizes the OS firewall rules automatically.
func (r *Router) SyncPortListener(port uint32) {
	if r.IsReservedPort(port) {
		log.Printf("[Ingress] Refusing to synchronize reserved port %d", port)
		return
	}

	r.mu.Lock()

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

	var openTCP, closeTCP, openUDP, closeUDP bool

	// Synchronize TCP listener
	if hasTCP {
		if _, exists := r.tcpListeners[port]; !exists {
			ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
			if err == nil {
				r.tcpListeners[port] = ln
				go r.acceptTCP(port, ln)
				openTCP = true
				log.Printf("[Ingress] Listening for public TCP traffic on 0.0.0.0:%d", port)
			} else {
				log.Printf("[Ingress] Failed to bind TCP listener on port %d: %v", port, err)
			}
		}
	} else {
		if ln, exists := r.tcpListeners[port]; exists {
			ln.Close()
			delete(r.tcpListeners, port)
			closeTCP = true
			log.Printf("[Ingress] Closed public TCP listener on port %d", port)
		}
	}

	// Synchronize UDP listener
	if hasUDP {
		if _, exists := r.udpListeners[port]; !exists {
			addr := &net.UDPAddr{IP: net.IPv4zero, Port: int(port)}
			uln, err := net.ListenUDP("udp", addr)
			if err == nil {
				_ = uln.SetReadBuffer(4 * 1024 * 1024)
				_ = uln.SetWriteBuffer(4 * 1024 * 1024)
				r.udpListeners[port] = uln
				go r.acceptUDP(port, uln)
				openUDP = true
				log.Printf("[Ingress] Listening for public UDP traffic on 0.0.0.0:%d", port)
			} else {
				log.Printf("[Ingress] Failed to bind UDP listener on port %d: %v", port, err)
			}
		}
	} else {
		if uln, exists := r.udpListeners[port]; exists {
			uln.Close()
			delete(r.udpListeners, port)
			closeUDP = true
			log.Printf("[Ingress] Closed public UDP listener on port %d", port)
		}
	}

	r.mu.Unlock()

	// Synchronize firewall rules outside of r.mu lock
	if openTCP {
		if err := r.firewall.OpenPort(firewall.ProtocolTCP, uint16(port)); err != nil {
			log.Printf("[Ingress] Failed to open firewall TCP port %d: %v", port, err)
		}
	}
	if closeTCP {
		if err := r.firewall.ClosePort(firewall.ProtocolTCP, uint16(port)); err != nil {
			log.Printf("[Ingress] Failed to close firewall TCP port %d: %v", port, err)
		}
	}
	if openUDP {
		if err := r.firewall.OpenPort(firewall.ProtocolUDP, uint16(port)); err != nil {
			log.Printf("[Ingress] Failed to open firewall UDP port %d: %v", port, err)
		}
	}
	if closeUDP {
		if err := r.firewall.ClosePort(firewall.ProtocolUDP, uint16(port)); err != nil {
			log.Printf("[Ingress] Failed to close firewall UDP port %d: %v", port, err)
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

	// Check if this port uses SNI demuxing
	isSNI := false
	for _, reg := range regs {
		if reg.DemuxMode == control.DemuxMode_DEMUX_TLS_SNI || reg.SniHostname != "" {
			isSNI = true
			break
		}
	}

	var candidates []*control.ServiceRegistration
	var peekedBytes []byte

	if isSNI {
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

		// Collect all candidates matching SNI
		for _, reg := range regs {
			if reg.SniHostname == sniHost {
				candidates = append(candidates, reg)
			}
		}

		if len(candidates) == 0 {
			resetTCP(clientConn)
			return
		}
	} else {
		candidates = regs
	}

	// Phase 2: Origin Selection / Dispatch Policy
	var selectedReg *control.ServiceRegistration
	policy := candidates[0].Policy

	switch policy {
	case control.RoutingPolicy_CLUSTERED_RTT:
		selectedReg = r.selectLowestRTT(candidates)

	case control.RoutingPolicy_FAILOVER_STANDBY, control.RoutingPolicy_STRICT_SINGLETON:
		selectedReg = candidates[0]
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

	edgePriv := r.host.Peerstore().PrivKey(r.host.ID())
	_ = proxy.PipeTCPStreamWithSigner(clientConn, s, bindingID, hmacToken, selectedReg.EnableProxyProtocol, peekedBytes, edgePriv)
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

		if err := r.forwarder.ForwardPacket(originPeer, bindingID, hmacToken, clientAddr, uln, packetData); err != nil {
			if !p2pquic.IsDatagramTooLarge(err) {
				log.Printf("[Ingress] Failed to forward UDP packet on port %d to origin %s: %v", port, originPeer, err)
			}
		}
	}
}

func (r *Router) refreshPeerRTT(pID peer.ID) {
	ctx, cancel := context.WithTimeout(r.ctx, 500*time.Millisecond)
	defer cancel()
	resChan := ping.Ping(ctx, r.host, pID)
	var measured time.Duration
	select {
	case res := <-resChan:
		if res.Error == nil {
			measured = res.RTT
		} else {
			measured = 10 * time.Second
		}
	case <-ctx.Done():
		measured = 10 * time.Second
	}

	r.mu.Lock()
	r.pingCache[pID] = pingEntry{
		rtt:        measured,
		measuredAt: time.Now(),
		refreshing: false,
	}
	r.mu.Unlock()
}

// selectLowestRTT picks the origin with the lowest RTT using libp2p Ping with a 30s TTL cache.
func (r *Router) selectLowestRTT(candidates []*control.ServiceRegistration) *control.ServiceRegistration {
	if len(candidates) == 1 {
		return candidates[0]
	}

	var bestReg *control.ServiceRegistration
	bestRTT := time.Duration(1<<63 - 1)
	now := time.Now()

	for _, reg := range candidates {
		pID, err := peer.Decode(reg.OriginPeerId)
		if err != nil {
			continue
		}

		r.mu.RLock()
		entry, exists := r.pingCache[pID]
		r.mu.RUnlock()

		var cachedRTT time.Duration
		if !exists {
			r.refreshPeerRTT(pID)
			r.mu.RLock()
			entry = r.pingCache[pID]
			r.mu.RUnlock()
			cachedRTT = entry.rtt
		} else {
			cachedRTT = entry.rtt
			if now.Sub(entry.measuredAt) > PingCacheTTL && !entry.refreshing {
				r.mu.Lock()
				if cur, ok := r.pingCache[pID]; ok && !cur.refreshing {
					cur.refreshing = true
					r.pingCache[pID] = cur
					go r.refreshPeerRTT(pID)
				}
				r.mu.Unlock()
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

