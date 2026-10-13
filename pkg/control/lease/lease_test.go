package lease

import (
	"sync"
	"testing"
	"time"

	control "p2p-anycast/pkg/proto/control"
)

func TestLeaseRegistrationAndReaping(t *testing.T) {
	var evicted []*control.ServiceRegistration
	var mu sync.Mutex

	mgr := NewManager(Config{
		ReaperInterval: 20 * time.Millisecond,
		OnEvict: func(reg *control.ServiceRegistration) {
			mu.Lock()
			evicted = append(evicted, reg)
			mu.Unlock()
		},
	})
	defer mgr.Close()

	reg := &control.ServiceRegistration{
		BindingId:        []byte("binding-token-01"),
		ServiceId:        "test-service",
		OriginPeerId:     "origin-peer-1",
		PublicPort:       8080,
		Protocol:         control.TransportProtocol_TCP,
		Policy:           control.RoutingPolicy_CLUSTERED_RTT,
		LeaseDurationSec: 1, // 1 second TTL
	}

	if err := mgr.Register(reg); err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	regs := mgr.GetRegistrationsForPort(8080)
	if len(regs) != 1 {
		t.Fatalf("expected 1 registration, got %d", len(regs))
	}

	// Wait for expiration
	time.Sleep(1200 * time.Millisecond)

	regs = mgr.GetRegistrationsForPort(8080)
	if len(regs) != 0 {
		t.Fatalf("expected 0 registrations after expiry, got %d", len(regs))
	}

	mu.Lock()
	evictedCount := len(evicted)
	mu.Unlock()

	if evictedCount != 1 {
		t.Fatalf("expected 1 onEvict callback, got %d", evictedCount)
	}
}

func TestStrictSingletonFencing(t *testing.T) {
	mgr := NewManager(Config{
		ReaperInterval: 50 * time.Millisecond,
	})
	defer mgr.Close()

	var bID1 [16]byte
	copy(bID1[:], "binding-origin-1")

	reg1 := &control.ServiceRegistration{
		BindingId:        bID1[:],
		ServiceId:        "singleton-pbx",
		OriginPeerId:     "origin-1",
		PublicPort:       5060,
		Protocol:         control.TransportProtocol_UDP,
		Policy:           control.RoutingPolicy_STRICT_SINGLETON,
		LeaseDurationSec: 60,
		LeaseEpoch:       10,
	}

	if err := mgr.Register(reg1); err != nil {
		t.Fatalf("failed to register reg1: %v", err)
	}

	// Stale epoch from origin-2 must be rejected
	var bID2 [16]byte
	copy(bID2[:], "binding-origin-2")

	reg2Stale := &control.ServiceRegistration{
		BindingId:        bID2[:],
		ServiceId:        "singleton-pbx",
		OriginPeerId:     "origin-2",
		PublicPort:       5060,
		Protocol:         control.TransportProtocol_UDP,
		Policy:           control.RoutingPolicy_STRICT_SINGLETON,
		LeaseDurationSec: 60,
		LeaseEpoch:       9, // Stale!
	}

	if err := mgr.Register(reg2Stale); err == nil {
		t.Fatal("expected error registering stale epoch, got nil")
	}

	// Higher epoch from origin-2 must displace origin-1
	reg2Higher := &control.ServiceRegistration{
		BindingId:        bID2[:],
		ServiceId:        "singleton-pbx",
		OriginPeerId:     "origin-2",
		PublicPort:       5060,
		Protocol:         control.TransportProtocol_UDP,
		Policy:           control.RoutingPolicy_STRICT_SINGLETON,
		LeaseDurationSec: 60,
		LeaseEpoch:       15, // Higher!
	}

	if err := mgr.Register(reg2Higher); err != nil {
		t.Fatalf("failed to register higher epoch: %v", err)
	}

	// origin-1 should be evicted, origin-2 active
	regs := mgr.GetRegistrationsForPort(5060)
	if len(regs) != 1 {
		t.Fatalf("expected exactly 1 singleton registration, got %d", len(regs))
	}
	if regs[0].OriginPeerId != "origin-2" {
		t.Fatalf("expected active origin-2, got %s", regs[0].OriginPeerId)
	}
}

func TestEvictPeerOnDisconnect(t *testing.T) {
	mgr := NewManager(Config{})
	defer mgr.Close()

	var bID [16]byte
	copy(bID[:], "token-disconnect")

	reg := &control.ServiceRegistration{
		BindingId:        bID[:],
		ServiceId:        "test-service",
		OriginPeerId:     "peer-to-disconnect",
		PublicPort:       9000,
		Protocol:         control.TransportProtocol_TCP,
		Policy:           control.RoutingPolicy_STRICT_SINGLETON,
		LeaseDurationSec: 60,
	}

	mgr.Register(reg)
	if len(mgr.GetRegistrationsForPort(9000)) != 1 {
		t.Fatal("failed to register")
	}

	evicted := mgr.EvictPeer("peer-to-disconnect")
	if len(evicted) != 1 {
		t.Fatalf("expected 1 evicted, got %d", len(evicted))
	}

	if len(mgr.GetRegistrationsForPort(9000)) != 0 {
		t.Fatal("peer was not evicted immediately on disconnect")
	}
}

func TestMultipleOriginsSameServiceLease(t *testing.T) {
	mgr := NewManager(Config{})
	defer mgr.Close()

	var bID [16]byte
	copy(bID[:], "shared-binding-token")

	reg1 := &control.ServiceRegistration{
		BindingId:        bID[:],
		ServiceId:        "clustered-api",
		OriginPeerId:     "origin-node-1",
		PublicPort:       443,
		Protocol:         control.TransportProtocol_TCP,
		Policy:           control.RoutingPolicy_CLUSTERED_RTT,
		SniHostname:      "api.meshcast.local",
		DemuxMode:        control.DemuxMode_DEMUX_TLS_SNI,
		LeaseDurationSec: 60,
	}

	reg2 := &control.ServiceRegistration{
		BindingId:        bID[:],
		ServiceId:        "clustered-api",
		OriginPeerId:     "origin-node-2",
		PublicPort:       443,
		Protocol:         control.TransportProtocol_TCP,
		Policy:           control.RoutingPolicy_CLUSTERED_RTT,
		SniHostname:      "api.meshcast.local",
		DemuxMode:        control.DemuxMode_DEMUX_TLS_SNI,
		LeaseDurationSec: 60,
	}

	if err := mgr.Register(reg1); err != nil {
		t.Fatalf("failed to register origin 1: %v", err)
	}
	if err := mgr.Register(reg2); err != nil {
		t.Fatalf("failed to register origin 2: %v", err)
	}

	regs := mgr.GetRegistrationsForPort(443)
	if len(regs) != 2 {
		t.Fatalf("expected 2 registrations for port 443, got %d", len(regs))
	}

	byBinding := mgr.GetRegistrationsByBindingID(bID)
	if len(byBinding) != 2 {
		t.Fatalf("expected 2 registrations for binding ID, got %d", len(byBinding))
	}

	// Disconnecting Origin 1 should only remove Origin 1
	evicted := mgr.EvictPeer("origin-node-1")
	if len(evicted) != 1 {
		t.Fatalf("expected 1 evicted registration, got %d", len(evicted))
	}

	regs = mgr.GetRegistrationsForPort(443)
	if len(regs) != 1 {
		t.Fatalf("expected 1 remaining registration, got %d", len(regs))
	}
	if regs[0].OriginPeerId != "origin-node-2" {
		t.Fatalf("expected origin-node-2 to remain, got %s", regs[0].OriginPeerId)
	}
}

func TestSingletonScopedBySNIOnSharedPort(t *testing.T) {
	mgr := NewManager(Config{})
	defer mgr.Close()

	var bID1, bID2, bID3 [16]byte
	copy(bID1[:], "bID-sni1")
	copy(bID2[:], "bID-sni2")
	copy(bID3[:], "bID-sni1-new")

	reg1 := &control.ServiceRegistration{
		BindingId:        bID1[:],
		ServiceId:        "sip-core-1",
		OriginPeerId:     "origin-1",
		PublicPort:       443,
		Protocol:         control.TransportProtocol_TCP,
		Policy:           control.RoutingPolicy_STRICT_SINGLETON,
		SniHostname:      "sip1.meshcast.local",
		DemuxMode:        control.DemuxMode_DEMUX_TLS_SNI,
		LeaseDurationSec: 60,
		LeaseEpoch:       10,
	}

	reg2 := &control.ServiceRegistration{
		BindingId:        bID2[:],
		ServiceId:        "sip-core-2",
		OriginPeerId:     "origin-2",
		PublicPort:       443,
		Protocol:         control.TransportProtocol_TCP,
		Policy:           control.RoutingPolicy_STRICT_SINGLETON,
		SniHostname:      "sip2.meshcast.local",
		DemuxMode:        control.DemuxMode_DEMUX_TLS_SNI,
		LeaseDurationSec: 60,
		LeaseEpoch:       10,
	}

	if err := mgr.Register(reg1); err != nil {
		t.Fatalf("failed to register reg1: %v", err)
	}
	if err := mgr.Register(reg2); err != nil {
		t.Fatalf("failed to register reg2 on same port different SNI: %v", err)
	}

	if len(mgr.GetRegistrationsForPort(443)) != 2 {
		t.Fatalf("expected 2 active singleton registrations on shared port 443")
	}

	// Reg3 on sip1 with stale epoch should fail
	reg3Stale := &control.ServiceRegistration{
		BindingId:        bID3[:],
		ServiceId:        "sip-core-1",
		OriginPeerId:     "origin-3",
		PublicPort:       443,
		Protocol:         control.TransportProtocol_TCP,
		Policy:           control.RoutingPolicy_STRICT_SINGLETON,
		SniHostname:      "sip1.meshcast.local",
		DemuxMode:        control.DemuxMode_DEMUX_TLS_SNI,
		LeaseDurationSec: 60,
		LeaseEpoch:       8,
	}
	if err := mgr.Register(reg3Stale); err == nil {
		t.Fatal("expected stale epoch on sip1 to fail")
	}

	// Reg3 with higher epoch on sip1 should displace origin-1, but leave origin-2 untouched
	reg3Higher := &control.ServiceRegistration{
		BindingId:        bID3[:],
		ServiceId:        "sip-core-1",
		OriginPeerId:     "origin-3",
		PublicPort:       443,
		Protocol:         control.TransportProtocol_TCP,
		Policy:           control.RoutingPolicy_STRICT_SINGLETON,
		SniHostname:      "sip1.meshcast.local",
		DemuxMode:        control.DemuxMode_DEMUX_TLS_SNI,
		LeaseDurationSec: 60,
		LeaseEpoch:       20,
	}
	if err := mgr.Register(reg3Higher); err != nil {
		t.Fatalf("failed to register reg3 with higher epoch: %v", err)
	}

	regs := mgr.GetRegistrationsForPort(443)
	if len(regs) != 2 {
		t.Fatalf("expected 2 active registrations, got %d", len(regs))
	}

	origins := make(map[string]bool)
	for _, r := range regs {
		origins[r.OriginPeerId] = true
	}
	if !origins["origin-2"] || !origins["origin-3"] {
		t.Fatalf("expected origin-2 and origin-3 to be active, got %v", origins)
	}
}

