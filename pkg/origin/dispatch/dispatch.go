package dispatch

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	control "p2p-anycast/pkg/proto/control"
)

var (
	ErrRouteNotFound   = errors.New("route not found for binding ID")
	ErrInvalidTarget   = errors.New("invalid target endpoint format")
)

// Route defines the target socket and protocol for a registered service.
type Route struct {
	BindingID   [16]byte
	Target      string // "host:port", "127.0.0.1:port", or "unix:///path"
	Protocol    control.TransportProtocol
	PublicPort  uint32
	ServiceID   string
}

type cachedUDP struct {
	addr      *net.UDPAddr
	expiresAt time.Time
}

// Table is a thread-safe static route table for local/internal service dispatch.
type Table struct {
	mu       sync.RWMutex
	routes   map[[16]byte]Route
	udpCache map[[16]byte]cachedUDP
}

// NewTable creates a new static route table.
func NewTable() *Table {
	return &Table{
		routes:   make(map[[16]byte]Route),
		udpCache: make(map[[16]byte]cachedUDP),
	}
}

// AddRoute registers a route in the static route table.
func (t *Table) AddRoute(route Route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes[route.BindingID] = route
	delete(t.udpCache, route.BindingID)
}

// RemoveRoute removes a route and its cached UDP resolution from the dispatch table.
func (t *Table) RemoveRoute(bindingID [16]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.routes, bindingID)
	delete(t.udpCache, bindingID)
}

// ListRoutes returns a snapshot of all registered routes in the dispatch table.
func (t *Table) ListRoutes() []Route {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Route, 0, len(t.routes))
	for _, r := range t.routes {
		out = append(out, r)
	}
	return out
}

// GetRoute retrieves a route by its binding ID.
func (t *Table) GetRoute(bindingID [16]byte) (Route, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	r, ok := t.routes[bindingID]
	return r, ok
}

// DialTCP connects to the target endpoint configured for the binding ID.
func (t *Table) DialTCP(bindingID [16]byte) (net.Conn, error) {
	route, ok := t.GetRoute(bindingID)
	if !ok {
		return nil, ErrRouteNotFound
	}

	target := route.Target
	if strings.HasPrefix(target, "unix://") {
		socketPath := strings.TrimPrefix(target, "unix://")
		return net.DialTimeout("unix", socketPath, 5*time.Second)
	}

	// Dial host:port or cluster DNS FQDN
	return net.DialTimeout("tcp", target, 5*time.Second)
}

// ResolveUDPAddr resolves the backend target as a UDP address.
func (t *Table) ResolveUDPAddr(bindingID [16]byte) (*net.UDPAddr, error) {
	route, ok := t.GetRoute(bindingID)
	if !ok {
		return nil, ErrRouteNotFound
	}

	target := route.Target
	if strings.HasPrefix(target, "unix://") {
		return nil, fmt.Errorf("%w: unix domain sockets not supported for UDP", ErrInvalidTarget)
	}

	now := time.Now()
	t.mu.RLock()
	cached, hasCached := t.udpCache[bindingID]
	t.mu.RUnlock()

	if hasCached && now.Before(cached.expiresAt) {
		return cached.addr, nil
	}

	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	t.udpCache[bindingID] = cachedUDP{
		addr:      addr,
		expiresAt: now.Add(30 * time.Second),
	}
	t.mu.Unlock()

	return addr, nil
}
