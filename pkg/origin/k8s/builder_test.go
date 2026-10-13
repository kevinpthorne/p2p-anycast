package k8s

import (
	"testing"

	control "p2p-anycast/pkg/proto/control"
)

func TestBuildFromServiceDefaultStrictSingleton(t *testing.T) {
	services := []Service{
		{
			Metadata: ObjectMeta{
				Name:      "minecraft",
				Namespace: "gaming",
				Annotations: map[string]string{
					"p2p-anycast.io/expose": "true",
				},
			},
			Spec: ServiceSpec{
				Ports: []ServicePort{
					{
						Name:     "game",
						Protocol: "TCP",
						Port:     25565,
					},
				},
			},
		},
		{
			Metadata: ObjectMeta{
				Name:      "bedrock",
				Namespace: "gaming",
				Annotations: map[string]string{
					"anycast.io/expose": "true", // test shorthand prefix
				},
			},
			Spec: ServiceSpec{
				Ports: []ServicePort{
					{
						Name:     "bedrock-udp",
						Protocol: "UDP",
						Port:     19132,
					},
				},
			},
		},
		{
			Metadata: ObjectMeta{
				Name:      "internal-db",
				Namespace: "default",
				Annotations: map[string]string{
					"p2p-anycast.io/expose": "false", // should be ignored
				},
			},
			Spec: ServiceSpec{
				Ports: []ServicePort{
					{
						Port:     5432,
						Protocol: "TCP",
					},
				},
			},
		},
	}

	res := BuildServicesFromK8s(services, nil, BuilderOptions{})
	if len(res) != 2 {
		t.Fatalf("expected 2 exposed services, got %d", len(res))
	}

	// 1. Minecraft TCP
	mc := res[0]
	if mc.ServiceID != "minecraft" {
		t.Errorf("expected serviceID 'minecraft', got %q", mc.ServiceID)
	}
	if mc.Policy != control.RoutingPolicy_STRICT_SINGLETON {
		t.Errorf("expected STRICT_SINGLETON policy by default, got %v", mc.Policy)
	}
	if mc.Protocol != control.TransportProtocol_TCP {
		t.Errorf("expected TCP protocol, got %v", mc.Protocol)
	}
	if mc.PublicPort != 25565 {
		t.Errorf("expected public port 25565, got %d", mc.PublicPort)
	}
	if mc.Target != "minecraft.gaming.svc.cluster.local:25565" {
		t.Errorf("expected cluster FQDN target, got %q", mc.Target)
	}
	if mc.SNIHostname != "" {
		t.Errorf("expected empty SNIHostname, got %q", mc.SNIHostname)
	}

	// 2. Bedrock UDP
	bedrock := res[1]
	if bedrock.ServiceID != "bedrock" {
		t.Errorf("expected serviceID 'bedrock', got %q", bedrock.ServiceID)
	}
	if bedrock.Policy != control.RoutingPolicy_STRICT_SINGLETON {
		t.Errorf("expected STRICT_SINGLETON policy by default, got %v", bedrock.Policy)
	}
	if bedrock.Protocol != control.TransportProtocol_UDP {
		t.Errorf("expected UDP protocol, got %v", bedrock.Protocol)
	}
	if bedrock.PublicPort != 19132 {
		t.Errorf("expected public port 19132, got %d", bedrock.PublicPort)
	}
	if bedrock.Target != "bedrock.gaming.svc.cluster.local:19132" {
		t.Errorf("expected cluster FQDN target, got %q", bedrock.Target)
	}
}

func TestBuildFromServiceMultiPortAndOverrides(t *testing.T) {
	services := []Service{
		{
			Metadata: ObjectMeta{
				Name:      "voip-pbx",
				Namespace: "telecom",
				Annotations: map[string]string{
					"p2p-anycast.io/expose":                     "true",
					"p2p-anycast.io/policy":                     "STRICT_SINGLETON",
					"p2p-anycast.io/target-type":                "localhost",
					"p2p-anycast.io/service-id.sip-udp":         "sip-signaling",
					"p2p-anycast.io/public-port.sip-udp":        "5060",
					"p2p-anycast.io/enable-proxy-protocol.http": "true",
				},
			},
			Spec: ServiceSpec{
				Ports: []ServicePort{
					{
						Name:     "sip-udp",
						Protocol: "UDP",
						Port:     5060,
					},
					{
						Name:     "http",
						Protocol: "TCP",
						Port:     80,
					},
				},
			},
		},
	}

	res := BuildServicesFromK8s(services, nil, BuilderOptions{})
	if len(res) != 2 {
		t.Fatalf("expected 2 services, got %d", len(res))
	}

	sip := res[0]
	if sip.ServiceID != "sip-signaling" {
		t.Errorf("expected custom service ID 'sip-signaling', got %q", sip.ServiceID)
	}
	if sip.Target != "127.0.0.1:5060" {
		t.Errorf("expected localhost target from target-type, got %q", sip.Target)
	}
	if sip.Policy != control.RoutingPolicy_STRICT_SINGLETON {
		t.Errorf("expected STRICT_SINGLETON policy, got %v", sip.Policy)
	}

	httpSvc := res[1]
	if httpSvc.ServiceID != "voip-pbx-http" {
		t.Errorf("expected default multi-port service ID 'voip-pbx-http', got %q", httpSvc.ServiceID)
	}
	if !httpSvc.EnableProxyProtocol {
		t.Errorf("expected enableProxyProtocol = true on http port")
	}
}

func TestBuildFromTLSRoute(t *testing.T) {
	gwPort := int32(443)
	gatewayNs := "kube-system"

	routes := []TLSRoute{
		{
			Metadata: ObjectMeta{
				Name:      "api-tls",
				Namespace: "apps",
				Annotations: map[string]string{
					"p2p-anycast.io/expose": "true",
					// Explicitly testing CLUSTERED_RTT override on an SNI app
					"p2p-anycast.io/policy": "CLUSTERED_RTT",
				},
			},
			Spec: TLSRouteSpec{
				ParentRefs: []ParentReference{
					{
						Name:      "cilium-gateway",
						Namespace: &gatewayNs,
						Port:      &gwPort,
					},
				},
				Hostnames: []string{"api.example.com"},
			},
		},
		{
			Metadata: ObjectMeta{
				Name:      "dashboard-tls",
				Namespace: "apps",
				Annotations: map[string]string{
					"p2p-anycast.io/expose": "true",
					// Default policy (should be STRICT_SINGLETON)
				},
			},
			Spec: TLSRouteSpec{
				ParentRefs: []ParentReference{
					{
						Name:      "cilium-gateway",
						Namespace: &gatewayNs,
					},
				},
				Hostnames: []string{"dash.example.com"},
			},
		},
	}

	res := BuildServicesFromK8s(nil, routes, BuilderOptions{})
	if len(res) != 2 {
		t.Fatalf("expected 2 TLSRoute services, got %d", len(res))
	}

	api := res[0]
	if api.ServiceID != "api-tls" {
		t.Errorf("expected serviceID 'api-tls', got %q", api.ServiceID)
	}
	if api.SNIHostname != "api.example.com" {
		t.Errorf("expected SNIHostname 'api.example.com', got %q", api.SNIHostname)
	}
	if api.Policy != control.RoutingPolicy_CLUSTERED_RTT {
		t.Errorf("expected CLUSTERED_RTT policy, got %v", api.Policy)
	}
	if api.Target != "cilium-gateway.kube-system.svc.cluster.local:443" {
		t.Errorf("expected cilium gateway target, got %q", api.Target)
	}

	dash := res[1]
	if dash.ServiceID != "dashboard-tls" {
		t.Errorf("expected serviceID 'dashboard-tls', got %q", dash.ServiceID)
	}
	if dash.SNIHostname != "dash.example.com" {
		t.Errorf("expected SNIHostname 'dash.example.com', got %q", dash.SNIHostname)
	}
	if dash.Policy != control.RoutingPolicy_STRICT_SINGLETON {
		t.Errorf("expected STRICT_SINGLETON default policy for dash, got %v", dash.Policy)
	}
	if dash.Target != "cilium-gateway.kube-system.svc.cluster.local:443" {
		t.Errorf("expected cilium gateway target, got %q", dash.Target)
	}
}

func TestBuildFromServiceSNIHostnames(t *testing.T) {
	// Directly annotating Cilium Gateway Service with multiple hostnames
	services := []Service{
		{
			Metadata: ObjectMeta{
				Name:      "cilium-gateway",
				Namespace: "kube-system",
				Annotations: map[string]string{
					"p2p-anycast.io/expose":        "true",
					"p2p-anycast.io/sni-hostnames": "app1.example.com, app2.example.com",
				},
			},
			Spec: ServiceSpec{
				Ports: []ServicePort{
					{
						Name:     "https",
						Port:     443,
						Protocol: "TCP",
					},
				},
			},
		},
	}

	res := BuildServicesFromK8s(services, nil, BuilderOptions{})
	if len(res) != 2 {
		t.Fatalf("expected 2 services for 2 hostnames, got %d", len(res))
	}

	if res[0].SNIHostname != "app1.example.com" {
		t.Errorf("expected app1.example.com, got %q", res[0].SNIHostname)
	}
	if res[1].SNIHostname != "app2.example.com" {
		t.Errorf("expected app2.example.com, got %q", res[1].SNIHostname)
	}
	if res[0].Policy != control.RoutingPolicy_STRICT_SINGLETON {
		t.Errorf("expected STRICT_SINGLETON by default, got %v", res[0].Policy)
	}
	if res[0].Target != "cilium-gateway.kube-system.svc.cluster.local:443" {
		t.Errorf("expected target cilium-gateway, got %q", res[0].Target)
	}
}
