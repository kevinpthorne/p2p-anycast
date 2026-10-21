package stream

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"

	"p2p-anycast/pkg/control/binding"
	"p2p-anycast/pkg/edge/proxy"
	"p2p-anycast/pkg/origin/dispatch"
	identity "p2p-anycast/pkg/proto/identity"
	"p2p-anycast/pkg/transport/auth"
)

const (
	// PreambleReadTimeout is the maximum duration allowed for reading the 32-byte stream preamble.
	PreambleReadTimeout = 5 * time.Second
)

var (
	ErrInvalidHMAC = errors.New("invalid HMAC capability token")
)

// Handler processes inbound proxied TCP streams from Edge routers.
type Handler struct {
	mu            sync.RWMutex
	host          host.Host
	originKey     []byte
	routes        *dispatch.Table
	authenticator *auth.Authenticator
}

// NewHandler creates a new TCP stream handler on the Origin side.
func NewHandler(h host.Host, originKey []byte, routes *dispatch.Table) *Handler {
	handler := &Handler{
		host:      h,
		originKey: originKey,
		routes:    routes,
	}
	h.SetStreamHandler(proxy.TCPProtocolID, handler.handleStream)
	return handler
}

// SetAuthenticator configures the Authenticator used to verify that inbound streams originate from an authenticated Edge router.
func (h *Handler) SetAuthenticator(a *auth.Authenticator) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.authenticator = a
}

func (h *Handler) handleStream(s network.Stream) {
	defer s.Close()
	remotePeerID := s.Conn().RemotePeer()
	remotePeer := remotePeerID.String()

	h.mu.RLock()
	authn := h.authenticator
	h.mu.RUnlock()

	if authn != nil {
		claims, ok := authn.GetSession(remotePeerID)
		if !ok || claims == nil || claims.Role != identity.NodeRole_EDGE_ROUTER {
			log.Printf("[Origin] Rejecting TCP stream from unauthenticated or non-Edge peer %s", remotePeer)
			s.Reset()
			return
		}
	}

	// 1. Read 32-byte preamble: [binding_id (16B) | hmac_token (16B)] with strict deadline
	_ = s.SetReadDeadline(time.Now().Add(PreambleReadTimeout))
	var preamble [proxy.PreambleLength]byte
	if _, err := io.ReadFull(s, preamble[:]); err != nil {
		s.Reset()
		return
	}
	_ = s.SetReadDeadline(time.Time{})

	var bindingID [16]byte
	copy(bindingID[:], preamble[0:16])
	hmacToken := preamble[16:32]

	// 2. Resolve route
	route, ok := h.routes.GetRoute(bindingID)
	if !ok {
		log.Printf("[Origin] Failed to handle TCP stream from %s: no route for binding ID %x", remotePeer, bindingID)
		s.Reset()
		return
	}

	// 3. Verify HMAC token strictly bound to the remote Edge's Peer ID
	if !binding.VerifyHMAC(h.originKey, remotePeer, route.PublicPort, bindingID, hmacToken) {
		log.Printf("[Origin] Failed to handle TCP stream from %s for service %s (port %d): HMAC verification failed",
			remotePeer, route.ServiceID, route.PublicPort)
		s.Reset()
		return
	}

	// 4. Dial target service
	backendConn, err := h.routes.DialTCP(bindingID)
	if err != nil {
		log.Printf("[Origin] Failed to dial backend TCP target %s for service %s: %v",
			route.Target, route.ServiceID, err)
		s.Reset()
		return
	}
	defer backendConn.Close()

	// 5. Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	// Stream -> Backend
	go func() {
		defer wg.Done()
		_, _ = io.Copy(backendConn, s)
		if tcpConn, ok := backendConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()

	// Backend -> Stream
	go func() {
		defer wg.Done()
		_, _ = io.Copy(s, backendConn)
		_ = s.CloseWrite()
	}()

	wg.Wait()
}

