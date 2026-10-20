package firewall

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type mockRunner struct {
	mu       sync.Mutex
	commands []string
}

func (m *mockRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cmdStr := name + " " + strings.Join(args, " ")
	m.commands = append(m.commands, cmdStr)
	return []byte("ok"), nil
}

func (m *mockRunner) hasCommand(sub string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.commands {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func (m *mockRunner) countCommand(sub string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, c := range m.commands {
		if strings.Contains(c, sub) {
			count++
		}
	}
	return count
}

func TestIptablesManager(t *testing.T) {
	mock := &mockRunner{}
	mgr, err := newIptablesManager(mock.Run)
	if err != nil {
		t.Fatalf("unexpected error creating iptables manager: %v", err)
	}

	// Verify chain was initialized
	if !mock.hasCommand("iptables -w 5 -N ANYCAST-EDGE") {
		t.Errorf("expected iptables -N ANYCAST-EDGE to be called")
	}

	// 1. Open port 8080 TCP
	if err := mgr.OpenPort(ProtocolTCP, 8080); err != nil {
		t.Fatalf("OpenPort(8080) failed: %v", err)
	}
	if !mock.hasCommand("iptables -w 5 -A ANYCAST-EDGE -p tcp --dport 8080 -j ACCEPT") {
		t.Errorf("expected iptables -A for port 8080 TCP")
	}

	// 2. Open port 8080 TCP again (idempotent / refcount)
	if err := mgr.OpenPort(ProtocolTCP, 8080); err != nil {
		t.Fatalf("OpenPort(8080) 2nd call failed: %v", err)
	}
	// Command should only have run once
	if cnt := mock.countCommand("iptables -w 5 -A ANYCAST-EDGE -p tcp --dport 8080 -j ACCEPT"); cnt != 1 {
		t.Errorf("expected 1 iptables -A command, got %d", cnt)
	}

	// 3. Open port 5060 UDP
	if err := mgr.OpenPort(ProtocolUDP, 5060); err != nil {
		t.Fatalf("OpenPort(5060) failed: %v", err)
	}
	if !mock.hasCommand("iptables -w 5 -A ANYCAST-EDGE -p udp --dport 5060 -j ACCEPT") {
		t.Errorf("expected iptables -A for port 5060 UDP")
	}

	// 4. Close 1 reference of port 8080 (should still be open)
	if err := mgr.ClosePort(ProtocolTCP, 8080); err != nil {
		t.Fatalf("ClosePort failed: %v", err)
	}
	if mock.hasCommand("iptables -w 5 -D ANYCAST-EDGE -p tcp --dport 8080") {
		t.Errorf("expected port 8080 to not be deleted yet since refcount was 2")
	}

	// 5. Close 2nd reference of port 8080 (now should delete rule)
	if err := mgr.ClosePort(ProtocolTCP, 8080); err != nil {
		t.Fatalf("ClosePort 2nd failed: %v", err)
	}
	if !mock.hasCommand("iptables -w 5 -D ANYCAST-EDGE -p tcp --dport 8080 -j ACCEPT") {
		t.Errorf("expected iptables -D for port 8080")
	}

	// 6. Close Manager (cleanup)
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if !mock.hasCommand("iptables -w 5 -F ANYCAST-EDGE") {
		t.Errorf("expected iptables -F ANYCAST-EDGE")
	}
	if !mock.hasCommand("iptables -w 5 -X ANYCAST-EDGE") {
		t.Errorf("expected iptables -X ANYCAST-EDGE")
	}
}

func TestNftablesManager(t *testing.T) {
	mock := &mockRunner{}
	mgr, err := newNftablesManagerWithTable(mock.Run, "anycast-edge")
	if err != nil {
		t.Fatalf("unexpected error creating nftables manager: %v", err)
	}

	// Verify table and sets initialized
	if !mock.hasCommand("nft add table inet anycast-edge") {
		t.Errorf("expected nft add table")
	}
	if !mock.hasCommand("nft add set inet anycast-edge anycast_tcp") {
		t.Errorf("expected nft add set tcp")
	}

	// Open port 443 TCP
	if err := mgr.OpenPort(ProtocolTCP, 443); err != nil {
		t.Fatalf("OpenPort(443) failed: %v", err)
	}
	if !mock.hasCommand("nft add element inet anycast-edge anycast_tcp { 443 }") {
		t.Errorf("expected nft add element for port 443")
	}

	// Close port 443 TCP
	if err := mgr.ClosePort(ProtocolTCP, 443); err != nil {
		t.Fatalf("ClosePort(443) failed: %v", err)
	}
	if !mock.hasCommand("nft delete element inet anycast-edge anycast_tcp { 443 }") {
		t.Errorf("expected nft delete element for port 443")
	}

	// Cleanup
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if !mock.hasCommand("nft delete table inet anycast-edge") {
		t.Errorf("expected nft delete table")
	}
}

func TestNftablesManagerNixOS(t *testing.T) {
	mock := &mockRunner{}
	mgr, err := newNftablesManagerWithTable(mock.Run, "nixos-fw")
	if err != nil {
		t.Fatalf("unexpected error creating nftables manager for nixos-fw: %v", err)
	}

	// Verify sets initialized in nixos-fw table
	if !mock.hasCommand("nft add set inet nixos-fw anycast_tcp") {
		t.Errorf("expected nft add set tcp in nixos-fw")
	}
	if !mock.hasCommand("nft add set inet nixos-fw anycast_udp") {
		t.Errorf("expected nft add set udp in nixos-fw")
	}

	// Verify rules are inserted into chain 'input' (NOT 'input-allow')
	if !mock.hasCommand("nft insert rule inet nixos-fw input tcp dport @anycast_tcp accept") {
		t.Errorf("expected nft insert rule into chain input for tcp")
	}
	if !mock.hasCommand("nft insert rule inet nixos-fw input udp dport @anycast_udp accept") {
		t.Errorf("expected nft insert rule into chain input for udp")
	}
	if mock.hasCommand("input-allow") {
		t.Errorf("unexpected reference to non-existent input-allow chain")
	}

	// Cleanup should flush sets instead of deleting table
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if !mock.hasCommand("nft flush set inet nixos-fw anycast_tcp") {
		t.Errorf("expected flush set anycast_tcp")
	}
	if !mock.hasCommand("nft flush set inet nixos-fw anycast_udp") {
		t.Errorf("expected flush set anycast_udp")
	}
	if mock.hasCommand("nft delete table inet nixos-fw") {
		t.Errorf("should not delete nixos-fw table")
	}
}

func TestNftablesManagerReconcile(t *testing.T) {
	mock := &mockRunner{}
	mgr, err := newNftablesManagerWithTable(mock.Run, "nixos-fw")
	if err != nil {
		t.Fatalf("unexpected error creating nftables manager: %v", err)
	}
	defer mgr.Close()

	if err := mgr.OpenPort(ProtocolTCP, 25565); err != nil {
		t.Fatalf("OpenPort failed: %v", err)
	}
	if err := mgr.OpenPort(ProtocolUDP, 19132); err != nil {
		t.Fatalf("OpenPort failed: %v", err)
	}

	// Now simulate a ruleset wipe where "nft list set inet nixos-fw anycast_tcp" fails
	mock.mu.Lock()
	mock.commands = nil
	mock.mu.Unlock()

	// Make mock return error for "list set"
	customRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmdStr := name + " " + strings.Join(args, " ")
		if strings.Contains(cmdStr, "list set inet nixos-fw anycast_tcp") {
			return nil, fmt.Errorf("Error: No such file or directory")
		}
		return mock.Run(ctx, name, args...)
	}

	mgr.mu.Lock()
	mgr.runner = customRunner
	mgr.mu.Unlock()

	// Trigger reconcile
	mgr.reconcile()

	// Verify that sets and elements were restored
	if !mock.hasCommand("nft add set inet nixos-fw anycast_tcp") {
		t.Errorf("expected reconcile to re-add set anycast_tcp")
	}
	if !mock.hasCommand("nft add element inet nixos-fw anycast_tcp { 25565 }") {
		t.Errorf("expected reconcile to restore port 25565 TCP")
	}
	if !mock.hasCommand("nft add element inet nixos-fw anycast_udp { 19132 }") {
		t.Errorf("expected reconcile to restore port 19132 UDP")
	}
}

func TestNoopManager(t *testing.T) {
	mgr := NewNoopManager()
	if err := mgr.OpenPort(ProtocolTCP, 80); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if err := mgr.ClosePort(ProtocolTCP, 80); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if err := mgr.Close(); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestNewFactory(t *testing.T) {
	mgr, err := New("none")
	if err != nil {
		t.Fatalf("unexpected error for none: %v", err)
	}
	if _, ok := mgr.(*NoopManager); !ok {
		t.Errorf("expected *NoopManager, got %T", mgr)
	}

	_, err = New("invalid-backend")
	if err == nil {
		t.Errorf("expected error for invalid backend")
	}
}
