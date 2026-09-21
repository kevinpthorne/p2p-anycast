package lease

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	control "p2p-anycast/pkg/proto/control"
)

const (
	DefaultLeaseTTL         = 60 * time.Second
	DefaultHeartbeatInterval = 20 * time.Second
	MaxMissedHeartbeats     = 3
)

var (
	ErrFencingEpochStale   = errors.New("lease epoch is stale (fenced out)")
	ErrRegistrationNotFound = errors.New("service registration not found")
	ErrSingletonConflict   = errors.New("strict singleton port already occupied by an active origin")
)

type LeaseRecord struct {
	Registration  *control.ServiceRegistration
	LastHeartbeat time.Time
	ExpiresAt     time.Time
	Active        bool
}

type Manager struct {
	mu           sync.RWMutex
	records      map[[16]byte]*LeaseRecord // binding_id -> record
	peerBindings map[string][][16]byte     // origin_peer_id -> binding_ids
	portPolicies map[uint32]*singletonState
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
	OnRegister func(reg *control.ServiceRegistration)
	OnEvict    func(reg *control.ServiceRegistration)
	ReaperInterval time.Duration
}

// NewManager creates a new lease manager.
func NewManager(cfg Config) *Manager {
	reaperInterval := cfg.ReaperInterval
	if reaperInterval == 0 {
		reaperInterval = 1 * time.Second
	}

	m := &Manager{
		records:      make(map[[16]byte]*LeaseRecord),
		peerBindings: make(map[string][][16]byte),
		portPolicies: make(map[uint32]*singletonState),
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

	ttl := time.Duration(reg.LeaseDurationSec) * time.Second
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}

	now := time.Now()

	// Enforce STRICT_SINGLETON fencing
	if reg.Policy == control.RoutingPolicy_STRICT_SINGLETON {
		state, exists := m.portPolicies[reg.PublicPort]
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
				oldBID := state.bindingID
				if oldRec, ok := m.records[oldBID]; ok {
					delete(m.records, oldBID)
					if m.onEvict != nil {
						go m.onEvict(oldRec.Registration)
					}
				}
				state.activeOrigin = reg.OriginPeerId
				state.activeEpoch = reg.LeaseEpoch
				state.bindingID = bID
			}
		} else {
			m.portPolicies[reg.PublicPort] = &singletonState{
				activeOrigin: reg.OriginPeerId,
				activeEpoch:  reg.LeaseEpoch,
				bindingID:    bID,
			}
		}
	}

	rec, exists := m.records[bID]
	isNew := !exists
	if isNew {
		rec = &LeaseRecord{
			Registration: reg,
			Active:       true,
		}
		m.records[bID] = rec
		m.peerBindings[reg.OriginPeerId] = append(m.peerBindings[reg.OriginPeerId], bID)
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

	rec, exists := m.records[bindingID]
	if !exists {
		return ErrRegistrationNotFound
	}

	if rec.Registration.OriginPeerId != originPeerID {
		return errors.New("heartbeat peer ID mismatch")
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

	rec.LastHeartbeat = now
	rec.ExpiresAt = now.Add(ttl)
	rec.Active = true

	return nil
}

// Revoke explicitly unregisters a service.
func (m *Manager) Revoke(originPeerID string, bindingID [16]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, exists := m.records[bindingID]
	if !exists {
		return ErrRegistrationNotFound
	}

	if rec.Registration.OriginPeerId != originPeerID {
		return errors.New("revoke origin peer ID mismatch")
	}

	m.evictRecord(bindingID, rec)
	return nil
}

// EvictPeer immediately evicts all active leases for a disconnected peer.
func (m *Manager) EvictPeer(originPeerID string) []*control.ServiceRegistration {
	m.mu.Lock()
	defer m.mu.Unlock()

	bIDs := m.peerBindings[originPeerID]
	var evicted []*control.ServiceRegistration

	for _, bID := range bIDs {
		if rec, ok := m.records[bID]; ok {
			evicted = append(evicted, rec.Registration)
			m.evictRecord(bID, rec)
		}
	}

	delete(m.peerBindings, originPeerID)
	return evicted
}

func (m *Manager) evictRecord(bID [16]byte, rec *LeaseRecord) {
	delete(m.records, bID)

	// Clean up singleton tracking if applicable
	if rec.Registration.Policy == control.RoutingPolicy_STRICT_SINGLETON {
		if state, ok := m.portPolicies[rec.Registration.PublicPort]; ok && bytes.Equal(state.bindingID[:], bID[:]) {
			delete(m.portPolicies, rec.Registration.PublicPort)
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
	var toEvict [][16]byte
	var toEvictRecs []*LeaseRecord

	for bID, rec := range m.records {
		if now.After(rec.ExpiresAt) {
			toEvict = append(toEvict, bID)
			toEvictRecs = append(toEvictRecs, rec)
		}
	}

	for i, bID := range toEvict {
		m.evictRecord(bID, toEvictRecs[i])
	}
	m.mu.Unlock()
}

// GetRegistrationsForPort returns all active registrations for the given port.
func (m *Manager) GetRegistrationsForPort(port uint32) []*control.ServiceRegistration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*control.ServiceRegistration
	for _, rec := range m.records {
		if rec.Registration.PublicPort == port {
			result = append(result, rec.Registration)
		}
	}
	return result
}

// GetRegistrationByBindingID returns the registration for a specific binding_id.
func (m *Manager) GetRegistrationByBindingID(bindingID [16]byte) (*control.ServiceRegistration, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec, ok := m.records[bindingID]
	if !ok {
		return nil, false
	}
	return rec.Registration, true
}
