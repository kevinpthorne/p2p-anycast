package nat

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2p-anycast/pkg/control/binding"
	"p2p-anycast/pkg/edge/forwarder"
	"p2p-anycast/pkg/origin/dispatch"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

const (
	SIPPort          = 5060
	SIPIdleTimeout   = 60 * time.Second
	RTPIdleTimeout   = 10 * time.Second
	DefaultIdleTimeout = 30 * time.Second
)

// SessionKey uniquely identifies a client flow arriving from an Edge.
type SessionKey struct {
	EdgePeerID string
	FlowID     uint32
	ClientIP   string
	ClientPort uint16
}

type SessionRecord struct {
	key           SessionKey
	ephemeralConn *net.UDPConn
	targetAddr    *net.UDPAddr
	publicPort    uint32
	lastSeenNano  atomic.Int64
}

func (s *SessionRecord) touch() {
	s.lastSeenNano.Store(time.Now().UnixNano())
}

func (s *SessionRecord) lastSeen() time.Time {
	return time.Unix(0, s.lastSeenNano.Load())
}

// Table manages stateful user-space UDP NAT bindings on the Origin.
type Table struct {
	mu          sync.RWMutex
	host        host.Host
	originKey   []byte
	routes      *dispatch.Table
	sessions    map[SessionKey]*SessionRecord
	ctx         context.Context
	cancel      context.CancelFunc
	reapTicker  *time.Ticker
	onSessionClosed func(key SessionKey)
}

// Config configures the NAT table.
type Config struct {
	ReaperInterval  time.Duration
	OnSessionClosed func(key SessionKey)
}

// NewTable initializes the NAT table.
func NewTable(ctx context.Context, h host.Host, originKey []byte, routes *dispatch.Table, cfg ...Config) *Table {
	tCtx, cancel := context.WithCancel(ctx)

	reaperInterval := 5 * time.Second
	var onClosed func(key SessionKey)
	if len(cfg) > 0 {
		if cfg[0].ReaperInterval > 0 {
			reaperInterval = cfg[0].ReaperInterval
		}
		onClosed = cfg[0].OnSessionClosed
	}

	t := &Table{
		host:            h,
		originKey:       originKey,
		routes:          routes,
		sessions:        make(map[SessionKey]*SessionRecord),
		ctx:             tCtx,
		cancel:          cancel,
		reapTicker:      time.NewTicker(reaperInterval),
		onSessionClosed: onClosed,
	}

	go t.reaperLoop()
	return t
}

// Close terminates all ephemeral sockets and stops the reaper.
func (t *Table) Close() {
	t.cancel()
	t.reapTicker.Stop()

	t.mu.Lock()
	defer t.mu.Unlock()

	for k, s := range t.sessions {
		s.ephemeralConn.Close()
		delete(t.sessions, k)
	}
}

// HandleForwardDatagram processes an incoming forward envelope from an Edge.
func (t *Table) HandleForwardDatagram(edgePeer peer.ID, data []byte) error {
	env, err := forwarder.DecodeForwardEnvelope(data)
	if err != nil {
		return err
	}

	sessionKey := SessionKey{
		EdgePeerID: edgePeer.String(),
		FlowID:     env.FlowID,
		ClientIP:   env.ClientIP.String(),
		ClientPort: env.ClientPort,
	}

	// 1. Fast Path: Concurrent Read Lock Check (bypasses DNS resolution, HMAC calculation, and global write locks)
	t.mu.RLock()
	session, exists := t.sessions[sessionKey]
	if exists {
		session.touch()
		t.mu.RUnlock()
		_, err := session.ephemeralConn.WriteToUDP(env.Payload, session.targetAddr)
		return err
	}
	t.mu.RUnlock()

	// 2. Slow Path: New Session Handshake
	// 2a. Resolve Route
	route, ok := t.routes.GetRoute(env.BindingID)
	if !ok {
		return fmt.Errorf("no route for binding ID")
	}

	// 2b. Verify HMAC Token (supports Origin-scoped mesh capability token + legacy Edge-scoped fallback)
	if !binding.VerifyHMACWithFallback(t.originKey, t.host.ID().String(), edgePeer.String(), route.PublicPort, env.BindingID, env.HMACToken[:]) {
		return fmt.Errorf("HMAC verification failed")
	}

	// 2c. Resolve Target Backend Address (uses cached DNS in routes table)
	targetAddr, err := t.routes.ResolveUDPAddr(env.BindingID)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP target: %w", err)
	}

	// 2d. Session Lookup or Allocation under Write Lock
	t.mu.Lock()
	session, exists = t.sessions[sessionKey]
	if !exists {
		// Bind ephemeral UDP socket (wildcard so kernel routes to target subnet)
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if err != nil {
			t.mu.Unlock()
			return fmt.Errorf("failed to allocate ephemeral UDP socket: %w", err)
		}

		_ = conn.SetReadBuffer(4 * 1024 * 1024)
		_ = conn.SetWriteBuffer(4 * 1024 * 1024)

		session = &SessionRecord{
			key:           sessionKey,
			ephemeralConn: conn,
			targetAddr:    targetAddr,
			publicPort:    route.PublicPort,
		}
		session.touch()
		t.sessions[sessionKey] = session

		// Spawn receiver goroutine for return packets
		go t.receiveReturnTraffic(edgePeer, env.FlowID, conn)
	} else {
		session.touch()
	}
	t.mu.Unlock()

	// 3. Forward packet from ephemeral socket to backend
	_, err = session.ephemeralConn.WriteToUDP(env.Payload, session.targetAddr)
	return err
}

// receiveReturnTraffic listens on the ephemeral socket for backend return packets and dispatches them via QUIC datagrams.
func (t *Table) receiveReturnTraffic(edgePeer peer.ID, flowID uint32, conn *net.UDPConn) {
	buf := make([]byte, 65535)
	sendBuf := make([]byte, forwarder.ReturnHeaderSize+65535)
	binary.BigEndian.PutUint32(sendBuf[0:4], flowID)

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // Socket closed
		}

		copy(sendBuf[forwarder.ReturnHeaderSize:forwarder.ReturnHeaderSize+n], buf[:n])
		if err := p2pquic.SendDatagram(t.host, edgePeer, sendBuf[:forwarder.ReturnHeaderSize+n]); err != nil {
			log.Printf("[NAT] Warning: failed to send return datagram to edge %s for flow %d: %v", edgePeer, flowID, err)
		}
	}
}

// reaperLoop sweeps idle flows periodically.
func (t *Table) reaperLoop() {
	for {
		select {
		case <-t.ctx.Done():
			return
		case now := <-t.reapTicker.C:
			t.sweepIdleSessions(now)
		}
	}
}

func (t *Table) sweepIdleSessions(now time.Time) {
	t.mu.Lock()
	var toEvict []*SessionRecord

	for _, s := range t.sessions {
		idleDuration := now.Sub(s.lastSeen())
		timeout := DefaultIdleTimeout

		if s.publicPort == SIPPort {
			timeout = SIPIdleTimeout
		} else if s.publicPort >= 10000 && s.publicPort <= 20000 {
			timeout = RTPIdleTimeout
		}

		if idleDuration > timeout {
			toEvict = append(toEvict, s)
		}
	}

	for _, s := range toEvict {
		s.ephemeralConn.Close()
		delete(t.sessions, s.key)
		if t.onSessionClosed != nil {
			t.onSessionClosed(s.key)
		}
	}
	t.mu.Unlock()
}

// ActiveSessionCount returns the number of currently active NAT sessions.
func (t *Table) ActiveSessionCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}
