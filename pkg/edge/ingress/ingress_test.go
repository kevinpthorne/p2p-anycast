package ingress

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"p2p-anycast/pkg/control/lease"
	"p2p-anycast/pkg/edge/firewall"
	"p2p-anycast/pkg/pki/keystore"
	control "p2p-anycast/pkg/proto/control"
	p2pquic "p2p-anycast/pkg/transport/quic"
)

type testFirewallMock struct {
	opened []string
	closed []string
}

func (m *testFirewallMock) OpenPort(proto firewall.Protocol, port uint16) error {
	m.opened = append(m.opened, fmt.Sprintf("%s:%d", proto, port))
	return nil
}

func (m *testFirewallMock) ClosePort(proto firewall.Protocol, port uint16) error {
	m.closed = append(m.closed, fmt.Sprintf("%s:%d", proto, port))
	return nil
}

func (m *testFirewallMock) Close() error {
	return nil
}

func TestEdgeDynamicListenerBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	key, _ := keystore.LoadOrGenerateIdentity(keystore.Options{ForceTier: keystore.TierRAM})
	h, err := p2pquic.NewHost(ctx, key, []string{"/ip4/127.0.0.1/udp/0/quic-v1"})
	if err != nil {
		t.Fatalf("failed to create host: %v", err)
	}
	defer h.Close()

	leaseMgr := lease.NewManager(lease.Config{})
	defer leaseMgr.Close()

	fwMock := &testFirewallMock{}
	router := NewRouter(ctx, h, leaseMgr, fwMock)
	defer router.Close()

	// Pick a free random port for testing
	tmpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	testPort := uint32(tmpLn.Addr().(*net.TCPAddr).Port)
	tmpLn.Close()

	var bID [16]byte
	copy(bID[:], "binding-token-42")

	reg := &control.ServiceRegistration{
		BindingId:        bID[:],
		ServiceId:        "test-tcp",
		OriginPeerId:     h.ID().String(),
		PublicPort:       testPort,
		Protocol:         control.TransportProtocol_TCP,
		Policy:           control.RoutingPolicy_CLUSTERED_RTT,
		LeaseDurationSec: 60,
	}

	// 1. Register service and sync listener
	if err := leaseMgr.Register(reg); err != nil {
		t.Fatalf("failed to register lease: %v", err)
	}
	router.SyncPortListener(testPort)

	// 2. Verify port is now bound and accepting TCP connects
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", testPort), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial bound port %d: %v", testPort, err)
	}
	conn.Close()

	expectedPortStr := fmt.Sprintf("tcp:%d", testPort)
	if len(fwMock.opened) != 1 || fwMock.opened[0] != expectedPortStr {
		t.Errorf("expected firewall opened %s, got %v", expectedPortStr, fwMock.opened)
	}

	// 3. Evict service and verify listener unbinds
	leaseMgr.Revoke(h.ID().String(), bID)
	router.SyncPortListener(testPort)

	// Should not be able to dial now
	connAfter, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", testPort), 200*time.Millisecond)
	if err == nil {
		connAfter.Close()
		t.Fatal("port is still accepting connections after unregister")
	}

	if len(fwMock.closed) != 1 || fwMock.closed[0] != expectedPortStr {
		t.Errorf("expected firewall closed %s, got %v", expectedPortStr, fwMock.closed)
	}
}
