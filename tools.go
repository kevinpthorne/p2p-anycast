//go:build tools
package tools

import (
	_ "github.com/cloudflare/circl/sign/mldsa/mldsa87"
	_ "github.com/google/go-tpm/legacy/tpm2"
	_ "github.com/libp2p/go-libp2p"
	_ "github.com/libp2p/go-libp2p-pubsub"
	_ "github.com/quic-go/quic-go"
	_ "google.golang.org/protobuf/proto"
	_ "lukechampine.com/blake3"
)
