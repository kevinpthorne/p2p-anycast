package lease

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	control "p2p-anycast/pkg/proto/control"
)

const (
	DefaultLeaseTTL          = 60 * time.Second
	MaxLeaseTTL              = 300 * time.Second
	DefaultHeartbeatInterval = 20 * time.Second
	MaxMissedHeartbeats      = 3
)

var (
	ErrFencingEpochStale    = errors.New("lease epoch is stale (fenced out)")
	ErrRegistrationNotFound = errors.New("service registration not found")
	ErrSingletonConflict    = errors.New("strict singleton port already occupied by an active origin")
	ErrPolicyConflict       = errors.New("routing policy or demux mode conflict on existing port/SNI binding")
)

type LeaseRecord struct {
	Registration  *control.ServiceRegistration
	RegisteredAt  time.Time
	LastHeartbeat time.Time
	ExpiresAt     time.Time
	Active        bool
}

type leaseKey struct {
	bindingID    [16]byte
	originPeerID string
}

type singletonKey struct {
	port        uint32
	sniHostname string
}

type Manager struct {
	mu           sync.RWMutex
	records      map[leaseKey]*LeaseRecord // (binding_id, origin_peer_id) -> record
	peerBindings map[string][]leaseKey     // origin_peer_id -> leaseKeys
	singletons   map[singletonKey]*singletonState
	onRegister   func(reg *control.ServiceRegistration)
	onEvict      func(reg *control.ServiceRegistration)
	ticker       *time.Ticker
	stopChan     chan struct{}
}

type singletonState struct {
	activeOrigin string
	activeEpoch  uint64
	bindingID    [16]byte
}

// Config allows configuring lease parameters.
type Config struct {
	OnRegister     func(reg *control.ServiceRegistration)
	OnEvict        func(reg *control.ServiceRegistration)
	ReaperInterval time.Duration
}

// NewManager creates a new lease manager.
func NewManager(cfg Config) *Manager {
	reaperInterval := cfg.ReaperInterval
	if reaperInterval == 0 {
		reaperInterval = 1 * time.Second
	}

	m := &Manager{
		records:      make(map[leaseKey]*LeaseRecord),
		peerBindings: make(map[string][]leaseKey),
		singletons:   make(map[singletonKey]*singletonState),
		onRegister:   cfg.OnRegister,
		onEvict:      cfg.OnEvict,
		ticker:       time.NewTicker(reaperInterval),
		stopChan:     make(chan struct{}),
	}

	go m.reaperLoop()
	return m
}

// Close stops the lease manager reaper.
func (m *Manager) Close() {
	close(m.stopChan)
	m.ticker.Stop()
}

// Register registers or updates a service registration.
func (m *Manager) Register(reg *control.ServiceRegistration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var bID [16]byte
	copy(bID[:], reg.BindingId)
	key := leaseKey{bindingID: bID, originPeerID: reg.OriginPeerId}

	ttl := time.Duration(reg.LeaseDurationSec) * time.Second
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	if ttl > MaxLeaseTTL {
		ttl = MaxLeaseTTL
	}

	now := time.Now()

	// Reject cross-demux conflicts on the same PublicPort or cross-policy conflicts on the same (PublicPort, SniHostname)
	for _, existing := range m.records {
		if existing.Registration.PublicPort == reg.PublicPort &&
			existing.Registration.OriginPeerId != reg.OriginPeerId {
			if existing.Registration.DemuxMode != reg.DemuxMode {
				return fmt.Errorf("%w: port %d active with demux %v, rejecting demux %v",
					ErrPolicyConflict, reg.PublicPort, existing.Registration.DemuxMode, reg.DemuxMode)
			}
			if existing.Registration.SniHostname == reg.SniHostname &&
				existing.Registration.Policy != reg.Policy {
				return fmt.Errorf("%w: port %d (sni %q) active with policy %v, rejecting %v",
					ErrPolicyConflict, reg.PublicPort, reg.SniHostname,
					existing.Registration.Policy, reg.Policy)
			}
		}
	}

	// Enforce STRICT_SINGLETON fencing per (port, sniHostname)
	if reg.Policy == control.RoutingPolicy_STRICT_SINGLETON {
		sKey := singletonKey{port: reg.PublicPort, sniHostname: reg.SniHostname}
		state, exists := m.singletons[sKey]
		if exists && state.activeOrigin != "" {
			if state.activeOrigin == reg.OriginPeerId {
				// Same origin updating
				if reg.LeaseEpoch < state.activeEpoch {
					return ErrFencingEpochStale
				}
				state.activeEpoch = reg.LeaseEpoch
			} else {
				// Different origin: enforce monotonic epoch fencing
				if reg.LeaseEpoch <= state.activeEpoch {
					return fmt.Errorf("%w: current active epoch %d >= incoming epoch %d", ErrFencingEpochStale, state.activeEpoch, reg.LeaseEpoch)
				}
				// New origin has strictly higher epoch -> displace old origin
				oldKey := leaseKey{bindingID: state.bindingID, originPeerID: state.activeOrigin}
				if oldRec, ok := m.records[oldKey]; ok {
					m.evictRecord(oldKey, oldRec)
				}
				state.activeOrigin = reg.OriginPeerId
				state.activeEpoch = reg.LeaseEpoch
				state.bindingID = bID
			}
		} else {
			m.singletons[sKey] = &singletonState{
				activeOrigin: reg.OriginPeerId,
				activeEpoch:  reg.LeaseEpoch,
				bindingID:    bID,
			}
		}
	}

	rec, exists := m.records[key]
	isNew := !exists
	if isNew {
		rec = &LeaseRecord{
			Registration: reg,
			RegisteredAt: now,
			Active:       true,
		}
		m.records[key] = rec
		m.peerBindings[reg.OriginPeerId] = append(m.peerBindings[reg.OriginPeerId], key)
	} else {
		rec.Registration = reg
		rec.Active = true
	}

	rec.LastHeartbeat = now
	rec.ExpiresAt = now.Add(ttl)

	if isNew && m.onRegister != nil {
		go m.onRegister(reg)
	}

	return nil
}

// Heartbeat refreshes an existing lease.
func (m *Manager) Heartbeat(originPeerID string, bindingID [16]byte, epoch uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := leaseKey{bindingID: bindingID, originPeerID: originPeerID}
	rec, exists := m.records[key]
	if !exists {
		return ErrRegistrationNotFound
	}

	// Enforce fencing epoch for singleton
	if rec.Registration.Policy == control.RoutingPolicy_STRICT_SINGLETON {
		if epoch < rec.Registration.LeaseEpoch {
			return ErrFencingEpochStale
		}
		rec.Registration.LeaseEpoch = epoch
	}

	now := time.Now()
	ttl := time.Duration(rec.Registration.LeaseDurationSec) * time.Second
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	if ttl > MaxLeaseTTL {
		ttl = MaxLeaseTTL
	}

	rec.LastHeartbeat = now
	rec.ExpiresAt = now.Add(ttl)
	rec.Active = true

	return nil
}

// Revoke explicitly unregisters a service.
func (m *Manager) Revoke(originPeerID string, bindingID [16]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := leaseKey{bindingID: bindingID, originPeerID: originPeerID}
	rec, exists := m.records[key]
	if !exists {
		return ErrRegistrationNotFound
	}

	m.evictRecord(key, rec)
	return nil
}

// EvictPeer immediately evicts all active leases for a disconnected peer.
func (m *Manager) EvictPeer(originPeerID string) []*control.ServiceRegistration {
	m.mu.Lock()
	defer m.mu.Unlock()

	keys := append([]leaseKey(nil), m.peerBindings[originPeerID]...)
	var evicted []*control.ServiceRegistration

	for _, key := range keys {
		if rec, ok := m.records[key]; ok {
			evicted = append(evicted, rec.Registration)
			m.evictRecord(key, rec)
		}
	}

	delete(m.peerBindings, originPeerID)
	return evicted
}

func (m *Manager) evictRecord(key leaseKey, rec *LeaseRecord) {
	delete(m.records, key)

	if bindings, ok := m.peerBindings[key.originPeerID]; ok {
		filtered := bindings[:0]
		for _, k := range bindings {
			if k != key {
				filtered = append(filtered, k)
			}
		}
		if len(filtered) == 0 {
			delete(m.peerBindings, key.originPeerID)
		} else {
			m.peerBindings[key.originPeerID] = filtered
		}
	}

	// Clean up singleton tracking if applicable
	if rec.Registration.Policy == control.RoutingPolicy_STRICT_SINGLETON {
		sKey := singletonKey{port: rec.Registration.PublicPort, sniHostname: rec.Registration.SniHostname}
		if state, ok := m.singletons[sKey]; ok && state.activeOrigin == rec.Registration.OriginPeerId {
			delete(m.singletons, sKey)
		}
	}

	if m.onEvict != nil {
		go m.onEvict(rec.Registration)
	}
}

// reaperLoop periodically sweeps for expired leases.
func (m *Manager) reaperLoop() {
	for {
		select {
		case <-m.stopChan:
			return
		case now := <-m.ticker.C:
			m.sweepExpired(now)
		}
	}
}

func (m *Manager) sweepExpired(now time.Time) {
	m.mu.Lock()
	var toEvict []leaseKey
	var toEvictRecs []*LeaseRecord

	for key, rec := range m.records {
		if now.After(rec.ExpiresAt) {
			toEvict = append(toEvict, key)
			toEvictRecs = append(toEvictRecs, rec)
		}
	}

	for i, key := range toEvict {
		m.evictRecord(key, toEvictRecs[i])
	}
	m.mu.Unlock()
}

func sortRecordsDeterministically(recs []*LeaseRecord) []*control.ServiceRegistration {
	sort.Slice(recs, func(i, j int) bool {
		if !recs[i].RegisteredAt.Equal(recs[j].RegisteredAt) {
			return recs[i].RegisteredAt.Before(recs[j].RegisteredAt)
		}
		return recs[i].Registration.OriginPeerId < recs[j].Registration.OriginPeerId
	})
	result := make([]*control.ServiceRegistration, len(recs))
	for i, r := range recs {
		result[i] = r.Registration
	}
	return result
}

// GetRegistrationsForPort returns all active registrations for the given port in deterministic order.
func (m *Manager) GetRegistrationsForPort(port uint32) []*control.ServiceRegistration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var recs []*LeaseRecord
	for _, rec := range m.records {
		if rec.Registration.PublicPort == port {
			recs = append(recs, rec)
		}
	}
	return sortRecordsDeterministically(recs)
}

// GetRegistrationByBindingID returns the primary (earliest registered) active registration for a specific binding_id.
func (m *Manager) GetRegistrationByBindingID(bindingID [16]byte) (*control.ServiceRegistration, bool) {
	regs := m.GetRegistrationsByBindingID(bindingID)
	if len(regs) == 0 {
		return nil, false
	}
	return regs[0], true
}

// GetRegistrationsByBindingID returns all active registrations for a specific binding_id across all origins in deterministic order.
func (m *Manager) GetRegistrationsByBindingID(bindingID [16]byte) []*control.ServiceRegistration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var recs []*LeaseRecord
	for key, rec := range m.records {
		if key.bindingID == bindingID {
			recs = append(recs, rec)
		}
	}
	return sortRecordsDeterministically(recs)
}

