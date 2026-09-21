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

// Table is a thread-safe static route table for local/internal service dispatch.
type Table struct {
	mu     sync.RWMutex
	routes map[[16]byte]Route
}

// NewTable creates a new static route table.
func NewTable() *Table {
	return &Table{
		routes: make(map[[16]byte]Route),
	}
}

// AddRoute registers a route in the static route table.
func (t *Table) AddRoute(route Route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes[route.BindingID] = route
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

	return net.ResolveUDPAddr("udp", target)
}
