package k8s

import (
	"fmt"
	"testing"

	"p2p-anycast/pkg/control/binding"
	control "p2p-anycast/pkg/proto/control"
)

func multiPortSNIService(annotation string) Service {
	return Service{
		Metadata: ObjectMeta{Name: "ovenmediaengine", Namespace: "streaming", Annotations: map[string]string{
			"p2p-anycast.io/expose": "true", annotation: "catcher.example.com", "p2p-anycast.io/public-port": "1936,3334",
		}},
		Spec: ServiceSpec{Ports: []ServicePort{{Name: "rtmps", Port: 1936, Protocol: "TCP"}, {Name: "whip", Port: 3334, Protocol: "TCP"}, {Name: "srt", Port: 8890, Protocol: "UDP"}}},
	}
}

func TestSNIServicePublicPortListUsesMatchingBackends(t *testing.T) {
	for _, annotation := range []string{"p2p-anycast.io/sni-hostname", "p2p-anycast.io/sni-hostnames"} {
		t.Run(annotation, func(t *testing.T) {
			svc := multiPortSNIService(annotation)
			routes := BuildServicesFromK8s([]Service{svc}, nil, BuilderOptions{DefaultGatewayTarget: "wrong-gateway.example.com:443"})
			if len(routes) != 2 {
				t.Fatalf("expected RTMPS and WHIP routes, got %+v", routes)
			}
			for i, port := range []uint32{1936, 3334} {
				route := routes[i]
				if route.PublicPort != port || route.Target != fmt.Sprintf("ovenmediaengine.streaming.svc.cluster.local:%d", port) || route.SNIHostname != "catcher.example.com" || route.Policy != control.RoutingPolicy_STRICT_SINGLETON || route.Protocol != control.TransportProtocol_TCP {
					t.Errorf("incorrect media route: %+v", route)
				}
			}
			first, second := routes[0], routes[1]
			if binding.DeriveBindingID(first.ServiceID, first.Protocol, first.PublicPort, first.SNIHostname) == binding.DeriveBindingID(second.ServiceID, second.Protocol, second.PublicPort, second.SNIHostname) {
				t.Fatal("different public ports must not replace each other's dispatch binding")
			}
		})
	}
}

func TestSNIPortListTrimsAndDeduplicatesAcrossHostnames(t *testing.T) {
	svc := multiPortSNIService("p2p-anycast.io/sni-hostnames")
	svc.Metadata.Annotations["p2p-anycast.io/sni-hostnames"] = "one.example.com, two.example.com"
	svc.Metadata.Annotations["p2p-anycast.io/public-port"] = " 1936 , 3334,1936 "
	routes := BuildServicesFromK8s([]Service{svc}, nil, BuilderOptions{})
	if len(routes) != 4 {
		t.Fatalf("expected one binding per distinct port and hostname, got %+v", routes)
	}
	seen := make(map[string]bool)
	for _, r := range routes {
		key := fmt.Sprintf("%d/%s", r.PublicPort, r.SNIHostname)
		if seen[key] {
			t.Fatalf("duplicate binding %s", key)
		}
		seen[key] = true
		if r.ServiceID != "ovenmediaengine-one-example-com" && r.ServiceID != "ovenmediaengine-two-example-com" {
			t.Errorf("unexpected identity %q", r.ServiceID)
		}
	}
}

func TestSNIPortListTargetOverridesAndUnmappedPorts(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Service)
		targets []string
	}{
		{"shared explicit backend", func(s *Service) {
			s.Metadata.Annotations["p2p-anycast.io/target"] = "proxy.streaming.svc.cluster.local:8443"
		}, []string{"proxy.streaming.svc.cluster.local:8443", "proxy.streaming.svc.cluster.local:8443"}},
		{"per-port backend", func(s *Service) {
			s.Metadata.Annotations["p2p-anycast.io/target.3334"] = "whip.streaming.svc.cluster.local:9443"
		}, []string{"ovenmediaengine.streaming.svc.cluster.local:1936", "whip.streaming.svc.cluster.local:9443"}},
		{"unmapped port", func(s *Service) { s.Spec.Ports = s.Spec.Ports[:1] }, nil},
		{"UDP-only port", func(s *Service) { s.Spec.Ports[1].Protocol = "UDP" }, nil},
		{"unsafe per-port backend", func(s *Service) { s.Metadata.Annotations["p2p-anycast.io/target.3334"] = "169.254.169.254:80" }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := multiPortSNIService("p2p-anycast.io/sni-hostnames")
			tc.mutate(&svc)
			routes := BuildServicesFromK8s([]Service{svc}, nil, BuilderOptions{})
			if len(routes) != len(tc.targets) {
				t.Fatalf("unexpected routes: %+v", routes)
			}
			for i, target := range tc.targets {
				if routes[i].Target != target {
					t.Errorf("got backend %q, want %q", routes[i].Target, target)
				}
			}
		})
	}
}

func TestInvalidSNIListNeverFallsBackOrPartiallyAdvertises(t *testing.T) {
	for _, value := range []string{"0", "65536", "-1", "1936,invalid", "1936,", "1936,,3334", "1936,65536", "443,0"} {
		t.Run(value, func(t *testing.T) {
			for _, annotation := range []string{"p2p-anycast.io/sni-hostname", "p2p-anycast.io/sni-hostnames"} {
				svc := multiPortSNIService(annotation)
				svc.Metadata.Annotations["p2p-anycast.io/public-port"] = value
				svc.Metadata.Annotations["p2p-anycast.io/target"] = "backend.example.com:443"
				if routes := BuildServicesFromK8s([]Service{svc}, nil, BuilderOptions{}); len(routes) != 0 {
					t.Errorf("invalid Service annotation advertised %+v", routes)
				}
			}
			route := TLSRoute{Metadata: ObjectMeta{Name: "media", Annotations: map[string]string{"p2p-anycast.io/expose": "true", "p2p-anycast.io/public-port": value, "p2p-anycast.io/target": "backend.example.com:443"}}, Spec: TLSRouteSpec{Hostnames: []string{"catcher.example.com"}}}
			if routes := BuildServicesFromK8s(nil, []TLSRoute{route}, BuilderOptions{}); len(routes) != 0 {
				t.Errorf("invalid TLSRoute annotation advertised %+v", routes)
			}
		})
	}
}

func TestTLSRoutePublicPortListPreservesGatewayBackend(t *testing.T) {
	port := int32(8443)
	route := TLSRoute{Metadata: ObjectMeta{Name: "media", Namespace: "streaming", Annotations: map[string]string{"p2p-anycast.io/expose": "true", "p2p-anycast.io/public-port": "1936,3334"}}, Spec: TLSRouteSpec{Hostnames: []string{"catcher.example.com"}, ParentRefs: []ParentReference{{Name: "gateway", Port: &port}}}}
	routes := BuildServicesFromK8s(nil, []TLSRoute{route}, BuilderOptions{})
	if len(routes) != 2 {
		t.Fatalf("expected both TLS listeners, got %+v", routes)
	}
	for i, port := range []uint32{1936, 3334} {
		r := routes[i]
		if r.PublicPort != port || r.Target != "gateway.streaming.svc.cluster.local:8443" || r.SNIHostname != "catcher.example.com" || r.ServiceID != "media" || r.Policy != control.RoutingPolicy_STRICT_SINGLETON {
			t.Errorf("incorrect TLSRoute binding: %+v", r)
		}
	}
}
