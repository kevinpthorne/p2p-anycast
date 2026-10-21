package quic

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/quic-go/quic-go"

	"p2p-anycast/pkg/pki/keystore"
)

var (
	ErrNoQUICConn         = errors.New("underlying connection is not a QUIC connection or does not support datagrams")
	ErrDatagramsDisabled  = errors.New("peer does not support QUIC datagrams")
)

// DefaultQUICConfig returns the quic.Config enforcing RFC 9221 datagrams.
func DefaultQUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:                  true,
		MaxIncomingStreams:               1024,
		MaxIncomingUniStreams:            64,
		MaxStreamReceiveWindow:           10 * (1 << 20), // 10 MB
		MaxConnectionReceiveWindow:       15 * (1 << 20), // 15 MB
		KeepAlivePeriod:                  10 * time.Second,
		EnableStreamResetPartialDelivery: true,
	}
}

// NewHost creates a new libp2p Host configured with native QUIC transport and datagram support.
func NewHost(ctx context.Context, idKey *keystore.IdentityKey, listenAddrs []string, extraOpts ...libp2p.Option) (host.Host, error) {
	opts := []libp2p.Option{
		libp2p.Identity(idKey.Libp2pPrivKey()),
		libp2p.ListenAddrStrings(listenAddrs...),
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.DisableRelay(),
	}

	opts = append(opts, extraOpts...)

	return libp2p.New(opts...)
}

// ExtractQUICConn unwraps the underlying *quic.Conn from a libp2p network.Conn.
func ExtractQUICConn(conn network.Conn) (*quic.Conn, error) {
	if conn == nil {
		return nil, errors.New("nil connection")
	}

	var qconn *quic.Conn
	if !conn.As(&qconn) || qconn == nil {
		return nil, ErrNoQUICConn
	}

	return qconn, nil
}

// SendDatagram sends an unreliable RFC 9221 datagram to the remote peer over their active QUIC connection.
func SendDatagram(h host.Host, remotePeer peer.ID, payload []byte) error {
	conns := h.Network().ConnsToPeer(remotePeer)
	if len(conns) == 0 {
		return fmt.Errorf("no active connection to peer %s", remotePeer)
	}

	// Iterate in reverse order to prefer the most recently established connection
	var lastErr error
	for i := len(conns) - 1; i >= 0; i-- {
		qconn, err := ExtractQUICConn(conns[i])
		if err == nil && qconn != nil {
			if sendErr := qconn.SendDatagram(payload); sendErr == nil {
				return nil
			} else {
				lastErr = sendErr
			}
		}
	}

	if lastErr != nil {
		return lastErr
	}
	return ErrNoQUICConn
}

// IsDatagramTooLarge reports whether err is a QUIC DatagramTooLargeError (e.g. from DPLPMTUD probes).
func IsDatagramTooLarge(err error) bool {
	var tooLarge *quic.DatagramTooLargeError
	return errors.As(err, &tooLarge)
}

// ReceiveDatagram reads the next incoming datagram from the specified connection.
func ReceiveDatagram(ctx context.Context, conn network.Conn) ([]byte, error) {
	qconn, err := ExtractQUICConn(conn)
	if err != nil {
		return nil, err
	}

	return qconn.ReceiveDatagram(ctx)
}
