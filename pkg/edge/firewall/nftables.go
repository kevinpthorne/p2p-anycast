package firewall

import (
	"context"
	"fmt"
	"log"
	"strings"
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
	ctx          context.Context
	cancel       context.CancelFunc
}

func newNftablesManager(runner commandRunner) (*NftablesManager, error) {
	return newNftablesManagerWithTable(runner, "")
}

func newNftablesManagerWithTable(runner commandRunner, preferredTable string) (*NftablesManager, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mCtx, mCancel := context.WithCancel(context.Background())
	mgr := &NftablesManager{
		runner:    runner,
		openPorts: make(map[string]int),
		ctx:       mCtx,
		cancel:    mCancel,
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
		mgr.cancel()
		return nil, fmt.Errorf("failed to initialize nftables table %s: %w", mgr.tableName, err)
	}

	go mgr.reconcileLoop()

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
	if out, err := m.runner(ctx, "nft", "add", "set", "inet", m.tableName, "anycast_tcp", "{ type inet_service; }"); err != nil {
		log.Printf("[Firewall] Warning: adding anycast_tcp set in table %s: %v (output: %s)", m.tableName, err, string(out))
	}
	if out, err := m.runner(ctx, "nft", "add", "set", "inet", m.tableName, "anycast_udp", "{ type inet_service; }"); err != nil {
		log.Printf("[Firewall] Warning: adding anycast_udp set in table %s: %v (output: %s)", m.tableName, err, string(out))
	}

	chainName := "input"
	// Check if rules are already present in chain input to prevent duplicates across restarts
	out, _ := m.runner(ctx, "nft", "list", "chain", "inet", m.tableName, chainName)
	chainContent := string(out)

	if !strings.Contains(chainContent, "@anycast_tcp") {
		var err error
		if m.isStandalone {
			_, err = m.runner(ctx, "nft", "add", "rule", "inet", m.tableName, chainName, "tcp", "dport", "@anycast_tcp", "accept")
		} else {
			// In NixOS nixos-fw table, insert at the beginning of chain input so it precedes reject/drop rules
			_, err = m.runner(ctx, "nft", "insert", "rule", "inet", m.tableName, chainName, "tcp", "dport", "@anycast_tcp", "accept")
		}
		if err != nil {
			log.Printf("[Firewall] Warning: failed to add tcp rule in table %s chain %s: %v", m.tableName, chainName, err)
		}
	}

	if !strings.Contains(chainContent, "@anycast_udp") {
		var err error
		if m.isStandalone {
			_, err = m.runner(ctx, "nft", "add", "rule", "inet", m.tableName, chainName, "udp", "dport", "@anycast_udp", "accept")
		} else {
			// In NixOS nixos-fw table, insert at the beginning of chain input so it precedes reject/drop rules
			_, err = m.runner(ctx, "nft", "insert", "rule", "inet", m.tableName, chainName, "udp", "dport", "@anycast_udp", "accept")
		}
		if err != nil {
			log.Printf("[Firewall] Warning: failed to add udp rule in table %s chain %s: %v", m.tableName, chainName, err)
		}
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
	if out, err := m.runner(ctx, "nft", "add", "element", "inet", m.tableName, setName, elem); err != nil {
		// Attempt auto-recovery if the set or rules were wiped
		if errInit := m.init(ctx); errInit == nil {
			if out2, err2 := m.runner(ctx, "nft", "add", "element", "inet", m.tableName, setName, elem); err2 == nil {
				m.openPorts[key] = 1
				log.Printf("[Firewall] Opened public %s port %d via nftables (after re-init)", proto, port)
				return nil
			} else {
				return fmt.Errorf("failed to add nft element %s to %s in table %s after re-init: %w (output: %s)", elem, setName, m.tableName, err2, string(out2))
			}
		}
		return fmt.Errorf("failed to add nft element %s to %s in table %s: %w (output: %s)", elem, setName, m.tableName, err, string(out))
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
	m.cancel()

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

func (m *NftablesManager) reconcileLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.reconcile()
		}
	}
}

func (m *NftablesManager) reconcile() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if anycast_tcp and anycast_udp sets exist
	needReinit := false
	if _, err := m.runner(ctx, "nft", "list", "set", "inet", m.tableName, "anycast_tcp"); err != nil {
		needReinit = true
	} else if _, err := m.runner(ctx, "nft", "list", "set", "inet", m.tableName, "anycast_udp"); err != nil {
		needReinit = true
	}

	if needReinit {
		log.Printf("[Firewall] Detected missing nftables sets in table %s (ruleset reflashed/reloaded). Re-synchronizing rules...", m.tableName)
		if err := m.init(ctx); err != nil {
			log.Printf("[Firewall] Error re-initializing nftables during reconcile: %v", err)
			return
		}
		// Re-add all currently active open ports
		for key, count := range m.openPorts {
			if count <= 0 {
				continue
			}
			parts := strings.Split(key, ":")
			if len(parts) != 2 {
				continue
			}
			proto := parts[0]
			port := parts[1]
			setName := "anycast_tcp"
			if proto == "udp" {
				setName = "anycast_udp"
			}
			elem := fmt.Sprintf("{ %s }", port)
			if out, err := m.runner(ctx, "nft", "add", "element", "inet", m.tableName, setName, elem); err != nil {
				log.Printf("[Firewall] Error restoring element %s in set %s: %v (output: %s)", elem, setName, err, string(out))
			} else {
				log.Printf("[Firewall] Restored dynamic %s port %s via nftables", proto, port)
			}
		}
	}
}
