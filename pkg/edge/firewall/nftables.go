package firewall

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// NftablesManager manages dynamic ports using nftables sets.
type NftablesManager struct {
	mu           sync.Mutex
	runner       commandRunner
	tableName    string
	isStandalone bool // true if managing dedicated inet anycast-edge table
	openPorts    map[string]int
	closed       bool
}

func newNftablesManager(runner commandRunner) (*NftablesManager, error) {
	return newNftablesManagerWithTable(runner, "")
}

func newNftablesManagerWithTable(runner commandRunner, preferredTable string) (*NftablesManager, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mgr := &NftablesManager{
		runner:    runner,
		openPorts: make(map[string]int),
	}

	if preferredTable != "" {
		mgr.tableName = preferredTable
		mgr.isStandalone = (preferredTable != "nixos-fw")
	} else {
		// Check if inet nixos-fw exists
		out, err := runner(ctx, "nft", "list", "table", "inet", "nixos-fw")
		if err == nil && len(out) > 0 {
			mgr.tableName = "nixos-fw"
			mgr.isStandalone = false
		} else {
			mgr.tableName = "anycast-edge"
			mgr.isStandalone = true
		}
	}

	if err := mgr.init(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize nftables table %s: %w", mgr.tableName, err)
	}

	log.Printf("[Firewall] Initialized nftables dynamic manager (table=%s, standalone=%v)", mgr.tableName, mgr.isStandalone)
	return mgr, nil
}

func (m *NftablesManager) init(ctx context.Context) error {
	if m.isStandalone {
		// Create dedicated table and hook chain
		if _, err := m.runner(ctx, "nft", "add", "table", "inet", m.tableName); err != nil {
			return fmt.Errorf("nft add table failed: %w", err)
		}
		if _, err := m.runner(ctx, "nft", "add", "chain", "inet", m.tableName, "input", "{ type filter hook input priority -10; policy accept; }"); err != nil {
			return fmt.Errorf("nft add chain failed: %w", err)
		}
	}

	// Create sets for TCP and UDP services
	_, _ = m.runner(ctx, "nft", "add", "set", "inet", m.tableName, "anycast_tcp", "{ type inet_service; }")
	_, _ = m.runner(ctx, "nft", "add", "set", "inet", m.tableName, "anycast_udp", "{ type inet_service; }")

	if m.isStandalone {
		_, _ = m.runner(ctx, "nft", "add", "rule", "inet", m.tableName, "input", "tcp", "dport", "@anycast_tcp", "accept")
		_, _ = m.runner(ctx, "nft", "add", "rule", "inet", m.tableName, "input", "udp", "dport", "@anycast_udp", "accept")
	} else {
		// Hook into NixOS input-allow chain
		_, _ = m.runner(ctx, "nft", "add", "rule", "inet", m.tableName, "input-allow", "tcp", "dport", "@anycast_tcp", "accept")
		_, _ = m.runner(ctx, "nft", "add", "rule", "inet", m.tableName, "input-allow", "udp", "dport", "@anycast_udp", "accept")
	}

	return nil
}

// OpenPort adds a port element into the corresponding nftables set.
func (m *NftablesManager) OpenPort(proto Protocol, port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("firewall manager is closed")
	}

	key := fmt.Sprintf("%s:%d", proto, port)
	if count := m.openPorts[key]; count > 0 {
		m.openPorts[key] = count + 1
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	setName := "anycast_tcp"
	if proto == ProtocolUDP {
		setName = "anycast_udp"
	}

	elem := fmt.Sprintf("{ %d }", port)
	if _, err := m.runner(ctx, "nft", "add", "element", "inet", m.tableName, setName, elem); err != nil {
		return fmt.Errorf("failed to add nft element %s to %s: %w", elem, setName, err)
	}

	m.openPorts[key] = 1
	log.Printf("[Firewall] Opened public %s port %d via nftables", proto, port)
	return nil
}

// ClosePort deletes a port element from the corresponding nftables set.
func (m *NftablesManager) ClosePort(proto Protocol, port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	key := fmt.Sprintf("%s:%d", proto, port)
	count := m.openPorts[key]
	if count <= 0 {
		return nil
	}
	if count > 1 {
		m.openPorts[key] = count - 1
		return nil
	}

	delete(m.openPorts, key)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	setName := "anycast_tcp"
	if proto == ProtocolUDP {
		setName = "anycast_udp"
	}

	elem := fmt.Sprintf("{ %d }", port)
	_, _ = m.runner(ctx, "nft", "delete", "element", "inet", m.tableName, setName, elem)

	log.Printf("[Firewall] Closed public %s port %d via nftables", proto, port)
	return nil
}

// Close cleans up nftables sets or table.
func (m *NftablesManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}
	m.closed = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if m.isStandalone {
		_, _ = m.runner(ctx, "nft", "delete", "table", "inet", m.tableName)
	} else {
		_, _ = m.runner(ctx, "nft", "flush", "set", "inet", m.tableName, "anycast_tcp")
		_, _ = m.runner(ctx, "nft", "flush", "set", "inet", m.tableName, "anycast_udp")
	}

	m.openPorts = make(map[string]int)
	log.Printf("[Firewall] Cleaned up nftables table %s", m.tableName)
	return nil
}
