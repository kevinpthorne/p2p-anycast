package forwarder

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	p2pquic "p2p-anycast/pkg/transport/quic"
)

const (
	// ForwardHeaderSize is 56 bytes:
	// binding_id(16B) + hmac_token(16B) + flow_id(4B) + client_ip(16B) + client_port(2B) + flags(2B)
	ForwardHeaderSize = 56

	// ReturnHeaderSize is 4 bytes: flow_id(4B)
	ReturnHeaderSize = 4
)

var (
	ErrPacketTooShort = errors.New("packet too short for datagram envelope")
)

// ForwardEnvelope represents a packet forwarded from Edge to Origin.
type ForwardEnvelope struct {
	BindingID  [16]byte
	HMACToken  [16]byte
	FlowID     uint32
	ClientIP   net.IP // 16 bytes
	ClientPort uint16
	Flags      uint16
	Payload    []byte
}

// Encode serializes the forward envelope into a byte slice.
func (f *ForwardEnvelope) Encode() []byte {
	buf := make([]byte, ForwardHeaderSize+len(f.Payload))
	copy(buf[0:16], f.BindingID[:])
	copy(buf[16:32], f.HMACToken[:])
	binary.BigEndian.PutUint32(buf[32:36], f.FlowID)

	ip16 := f.ClientIP.To16()
	if ip16 == nil {
		ip16 = net.IPv6zero
	}
	copy(buf[36:52], ip16)
	binary.BigEndian.PutUint16(buf[52:54], f.ClientPort)
	binary.BigEndian.PutUint16(buf[54:56], f.Flags)
	copy(buf[56:], f.Payload)

	return buf
}

// DecodeForwardEnvelope parses a raw forward datagram.
func DecodeForwardEnvelope(data []byte) (*ForwardEnvelope, error) {
	if len(data) < ForwardHeaderSize {
		return nil, ErrPacketTooShort
	}

	env := &ForwardEnvelope{}
	copy(env.BindingID[:], data[0:16])
	copy(env.HMACToken[:], data[16:32])
	env.FlowID = binary.BigEndian.Uint32(data[32:36])

	ip := make(net.IP, 16)
	copy(ip, data[36:52])
	env.ClientIP = ip
	env.ClientPort = binary.BigEndian.Uint16(data[52:54])
	env.Flags = binary.BigEndian.Uint16(data[54:56])
	env.Payload = data[56:]

	return env, nil
}

// ReturnEnvelope represents a return packet from Origin to Edge.
type ReturnEnvelope struct {
	FlowID  uint32
	Payload []byte
}

// Encode serializes the return envelope.
func (r *ReturnEnvelope) Encode() []byte {
	buf := make([]byte, ReturnHeaderSize+len(r.Payload))
	binary.BigEndian.PutUint32(buf[0:4], r.FlowID)
	copy(buf[4:], r.Payload)
	return buf
}

// DecodeReturnEnvelope parses a return datagram.
func DecodeReturnEnvelope(data []byte) (*ReturnEnvelope, error) {
	if len(data) < ReturnHeaderSize {
		return nil, ErrPacketTooShort
	}
	return &ReturnEnvelope{
		FlowID:  binary.BigEndian.Uint32(data[0:4]),
		Payload: data[4:],
	}, nil
}

type clientFlow struct {
	flowID     uint32
	clientAddr *net.UDPAddr
	listener   *net.UDPConn
	lastSeen   time.Time
}

// EdgeDatagramForwarder handles routing between public UDP listeners and QUIC datagrams.
type EdgeDatagramForwarder struct {
	mu           sync.RWMutex
	host         host.Host
	flowSeq      uint32
	flowsByAddr  map[string]*clientFlow // clientAddr.String() -> flow
	flowsByID    map[uint32]*clientFlow // flowID -> flow
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewEdgeDatagramForwarder creates a new forwarder on the Edge.
func NewEdgeDatagramForwarder(ctx context.Context, h host.Host) *EdgeDatagramForwarder {
	fCtx, cancel := context.WithCancel(ctx)
	f := &EdgeDatagramForwarder{
		host:        h,
		flowsByAddr: make(map[string]*clientFlow),
		flowsByID:   make(map[uint32]*clientFlow),
		ctx:         fCtx,
		cancel:      cancel,
	}

	go f.reaperLoop()
	return f
}

// Close stops the forwarder.
func (f *EdgeDatagramForwarder) Close() {
	f.cancel()
}

// GetOrCreateFlow retrieves or assigns a flow ID for a client UDP address.
func (f *EdgeDatagramForwarder) GetOrCreateFlow(clientAddr *net.UDPAddr, listener *net.UDPConn) uint32 {
	addrStr := clientAddr.String()

	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now()
	if flow, ok := f.flowsByAddr[addrStr]; ok {
		flow.lastSeen = now
		return flow.flowID
	}

	flowID := atomic.AddUint32(&f.flowSeq, 1)
	flow := &clientFlow{
		flowID:     flowID,
		clientAddr: clientAddr,
		listener:   listener,
		lastSeen:   now,
	}

	f.flowsByAddr[addrStr] = flow
	f.flowsByID[flowID] = flow
	return flowID
}

// ForwardPacket constructs a forward envelope and sends it via QUIC datagram to the target origin.
func (f *EdgeDatagramForwarder) ForwardPacket(targetOrigin peer.ID, bindingID [16]byte, hmacToken [16]byte, clientAddr *net.UDPAddr, listener *net.UDPConn, payload []byte) error {
	flowID := f.GetOrCreateFlow(clientAddr, listener)

	env := &ForwardEnvelope{
		BindingID:  bindingID,
		HMACToken:  hmacToken,
		FlowID:     flowID,
		ClientIP:   clientAddr.IP,
		ClientPort: uint16(clientAddr.Port),
		Flags:      0,
		Payload:    payload,
	}

	data := env.Encode()
	return p2pquic.SendDatagram(f.host, targetOrigin, data)
}

// HandleReturnDatagram routes an incoming return datagram from an Origin back to the original client.
func (f *EdgeDatagramForwarder) HandleReturnDatagram(data []byte) error {
	ret, err := DecodeReturnEnvelope(data)
	if err != nil {
		return err
	}

	f.mu.RLock()
	flow, ok := f.flowsByID[ret.FlowID]
	f.mu.RUnlock()

	if !ok || flow == nil || flow.listener == nil {
		return fmt.Errorf("unknown flow ID %d", ret.FlowID)
	}

	flow.lastSeen = time.Now()
	_, err = flow.listener.WriteToUDP(ret.Payload, flow.clientAddr)
	return err
}

// StartDatagramReceiver listens on all connections from an Origin peer for return datagrams.
func (f *EdgeDatagramForwarder) StartDatagramReceiver(conn network.Conn) {
	go func() {
		for {
			select {
			case <-f.ctx.Done():
				return
			default:
			}

			data, err := p2pquic.ReceiveDatagram(f.ctx, conn)
			if err != nil {
				return // Connection closed or context cancelled
			}

			_ = f.HandleReturnDatagram(data)
		}
	}()
}

func (f *EdgeDatagramForwarder) reaperLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-f.ctx.Done():
			return
		case now := <-ticker.C:
			f.sweepIdleFlows(now)
		}
	}
}

func (f *EdgeDatagramForwarder) sweepIdleFlows(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for id, flow := range f.flowsByID {
		if now.Sub(flow.lastSeen) > 60*time.Second {
			delete(f.flowsByID, id)
			delete(f.flowsByAddr, flow.clientAddr.String())
		}
	}
}
