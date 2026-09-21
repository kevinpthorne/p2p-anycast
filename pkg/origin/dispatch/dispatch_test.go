package dispatch

import (
	"net"
	"testing"

	control "p2p-anycast/pkg/proto/control"
)

func TestStaticRouteTable(t *testing.T) {
	table := NewTable()

	var bID [16]byte
	copy(bID[:], "minecraft-token1")

	route := Route{
		BindingID:  bID,
		Target:     "minecraft.minecraft.svc.cluster.local:25565",
		Protocol:   control.TransportProtocol_TCP,
		PublicPort: 25565,
		ServiceID:  "minecraft-smp",
	}

	table.AddRoute(route)

	retrieved, ok := table.GetRoute(bID)
	if !ok {
		t.Fatal("route not found")
	}

	if retrieved.Target != "minecraft.minecraft.svc.cluster.local:25565" {
		t.Fatalf("target mismatch: got %s", retrieved.Target)
	}

	// Test ResolveUDPAddr for localhost
	var bIDUDP [16]byte
	copy(bIDUDP[:], "pbx-token-sip001")
	table.AddRoute(Route{
		BindingID:  bIDUDP,
		Target:     "127.0.0.1:5060",
		Protocol:   control.TransportProtocol_UDP,
		PublicPort: 5060,
		ServiceID:  "pbx-core",
	})

	udpAddr, err := table.ResolveUDPAddr(bIDUDP)
	if err != nil {
		t.Fatalf("failed to resolve UDP addr: %v", err)
	}
	if udpAddr.Port != 5060 || !udpAddr.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("unexpected resolved address: %v", udpAddr)
	}
}
