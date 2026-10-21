package stream

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"

	"p2p-anycast/pkg/control/binding"
	"p2p-anycast/pkg/edge/proxy"
	"p2p-anycast/pkg/origin/dispatch"
)

var (
	ErrInvalidHMAC = errors.New("invalid HMAC capability token")
)

// Handler processes inbound proxied TCP streams from Edge routers.
type Handler struct {
	host      host.Host
	originKey []byte
	routes    *dispatch.Table
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

func (h *Handler) handleStream(s network.Stream) {
	defer s.Close()
	remotePeer := s.Conn().RemotePeer().String()

	// 1. Read 32-byte preamble: [binding_id (16B) | hmac_token (16B)]
	var preamble [proxy.PreambleLength]byte
	if _, err := io.ReadFull(s, preamble[:]); err != nil {
		s.Reset()
		return
	}

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

	// 3. Verify HMAC token (supports Origin-scoped mesh capability token + legacy Edge-scoped fallback)
	if !binding.VerifyHMACWithFallback(h.originKey, h.host.ID().String(), remotePeer, route.PublicPort, bindingID, hmacToken) {
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
