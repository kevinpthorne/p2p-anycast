package firewall

import (
	"context"
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
