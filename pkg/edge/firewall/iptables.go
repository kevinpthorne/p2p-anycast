package firewall

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	iptablesChain = "ANYCAST-EDGE"
)

// IptablesManager manages dynamic firewall ports using iptables and ip6tables.
type IptablesManager struct {
	mu          sync.Mutex
	runner      commandRunner
	parentChain string
	hasIPv6     bool
	openPorts   map[string]int
	closed      bool
}

func newIptablesManager(runner commandRunner) (*IptablesManager, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Detect parent chain: check if nixos-fw exists
	parent := "INPUT"
	if _, err := runner(ctx, "iptables", "-w", "5", "-n", "-L", "nixos-fw"); err == nil {
		parent = "nixos-fw"
	}

	// 2. Detect IPv6 support
	hasIPv6 := false
	if _, err := runner(ctx, "ip6tables", "-w", "5", "-n", "-L", "INPUT"); err == nil {
		hasIPv6 = true
	}

	mgr := &IptablesManager{
		runner:      runner,
		parentChain: parent,
		hasIPv6:     hasIPv6,
		openPorts:   make(map[string]int),
	}

	if err := mgr.initChain(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize iptables chain %s: %w", iptablesChain, err)
	}

	log.Printf("[Firewall] Initialized iptables dynamic manager (parent=%s, ipv6=%v)", parent, hasIPv6)
	return mgr, nil
}

func (m *IptablesManager) initChain(ctx context.Context) error {
	// Create chain if it doesn't already exist
	_, _ = m.runner(ctx, "iptables", "-w", "5", "-N", iptablesChain)
	if m.hasIPv6 {
		_, _ = m.runner(ctx, "ip6tables", "-w", "5", "-N", iptablesChain)
	}

	// Ensure parent chain jumps to ANYCAST-EDGE as rule #1
	if _, err := m.runner(ctx, "iptables", "-w", "5", "-C", m.parentChain, "-j", iptablesChain); err != nil {
		if _, err := m.runner(ctx, "iptables", "-w", "5", "-I", m.parentChain, "1", "-j", iptablesChain); err != nil {
			return fmt.Errorf("iptables jump insertion failed: %w", err)
		}
	}

	if m.hasIPv6 {
		if _, err := m.runner(ctx, "ip6tables", "-w", "5", "-C", m.parentChain, "-j", iptablesChain); err != nil {
			_, _ = m.runner(ctx, "ip6tables", "-w", "5", "-I", m.parentChain, "1", "-j", iptablesChain)
		}
	}

	return nil
}

// OpenPort opens the specified protocol and port in the ANYCAST-EDGE chain.
func (m *IptablesManager) OpenPort(proto Protocol, port uint16) error {
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

	portStr := fmt.Sprintf("%d", port)
	protoStr := string(proto)

	// Append rule to ANYCAST-EDGE chain
	if _, err := m.runner(ctx, "iptables", "-w", "5", "-A", iptablesChain, "-p", protoStr, "--dport", portStr, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to open %s port %d via iptables: %w", proto, port, err)
	}

	if m.hasIPv6 {
		_, _ = m.runner(ctx, "ip6tables", "-w", "5", "-A", iptablesChain, "-p", protoStr, "--dport", portStr, "-j", "ACCEPT")
	}

	m.openPorts[key] = 1
	log.Printf("[Firewall] Opened public %s port %d in firewall", proto, port)
	return nil
}

// ClosePort closes the specified protocol and port in the ANYCAST-EDGE chain.
func (m *IptablesManager) ClosePort(proto Protocol, port uint16) error {
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

	portStr := fmt.Sprintf("%d", port)
	protoStr := string(proto)

	// Delete rule from ANYCAST-EDGE chain
	_, _ = m.runner(ctx, "iptables", "-w", "5", "-D", iptablesChain, "-p", protoStr, "--dport", portStr, "-j", "ACCEPT")
	if m.hasIPv6 {
		_, _ = m.runner(ctx, "ip6tables", "-w", "5", "-D", iptablesChain, "-p", protoStr, "--dport", portStr, "-j", "ACCEPT")
	}

	log.Printf("[Firewall] Closed public %s port %d in firewall", proto, port)
	return nil
}

// Close removes all firewall rules, jumps, and deletes the ANYCAST-EDGE chain.
func (m *IptablesManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}
	m.closed = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Remove jump from parent chain
	_, _ = m.runner(ctx, "iptables", "-w", "5", "-D", m.parentChain, "-j", iptablesChain)
	if m.hasIPv6 {
		_, _ = m.runner(ctx, "ip6tables", "-w", "5", "-D", m.parentChain, "-j", iptablesChain)
	}

	// 2. Flush chain
	_, _ = m.runner(ctx, "iptables", "-w", "5", "-F", iptablesChain)
	if m.hasIPv6 {
		_, _ = m.runner(ctx, "ip6tables", "-w", "5", "-F", iptablesChain)
	}

	// 3. Delete chain
	_, _ = m.runner(ctx, "iptables", "-w", "5", "-X", iptablesChain)
	if m.hasIPv6 {
		_, _ = m.runner(ctx, "ip6tables", "-w", "5", "-X", iptablesChain)
	}

	m.openPorts = make(map[string]int)
	log.Printf("[Firewall] Flushed and deleted iptables chain %s", iptablesChain)
	return nil
}
