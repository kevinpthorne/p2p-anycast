package k8s

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestClientListServicesAndTLSRoutes(t *testing.T) {
	mockServices := ServiceList{
		APIVersion: "v1",
		Kind:       "ServiceList",
		Items: []Service{
			{
				Metadata: ObjectMeta{
					Name:      "minecraft",
					Namespace: "games",
					Annotations: map[string]string{
						"p2p-anycast.io/expose": "true",
					},
				},
				Spec: ServiceSpec{
					Ports: []ServicePort{
						{
							Name:     "tcp-game",
							Port:     25565,
							Protocol: "TCP",
						},
					},
				},
			},
		},
	}

	mockTLSRoutes := TLSRouteList{
		APIVersion: "gateway.networking.k8s.io/v1",
		Kind:       "TLSRouteList",
		Items: []TLSRoute{
			{
				Metadata: ObjectMeta{
					Name:      "web-tls",
					Namespace: "apps",
					Annotations: map[string]string{
						"p2p-anycast.io/expose": "true",
					},
				},
				Spec: TLSRouteSpec{
					Hostnames: []string{"web.example.com"},
				},
			},
		},
	}

	receivedToken := ""

	mockTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		receivedToken = req.Header.Get("Authorization")

		var body []byte
		statusCode := http.StatusOK

		switch req.URL.Path {
		case "/api/v1/services":
			body, _ = json.Marshal(mockServices)
		case "/apis/gateway.networking.k8s.io/v1/tlsroutes":
			body, _ = json.Marshal(mockTLSRoutes)
		default:
			statusCode = http.StatusNotFound
			body = []byte(`{"message": "not found"}`)
		}

		return &http.Response{
			StatusCode: statusCode,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})

	client, err := NewClient(ClientConfig{
		APIServerURL:          "https://mock-k8s.local",
		Token:                 "test-secret-token",
		InsecureSkipTLSVerify: true,
		Transport:             mockTransport,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	// 1. Test ListServices
	svcs, err := client.ListServices(ctx, "")
	if err != nil {
		t.Fatalf("ListServices failed: %v", err)
	}
	if len(svcs) != 1 {
		t.Fatalf("expected 1 service, got %d", len(svcs))
	}
	if svcs[0].Metadata.Name != "minecraft" {
		t.Errorf("expected service 'minecraft', got %q", svcs[0].Metadata.Name)
	}
	if receivedToken != "Bearer test-secret-token" {
		t.Errorf("expected Bearer token, got %q", receivedToken)
	}

	// 2. Test ListTLSRoutes
	routes, err := client.ListTLSRoutes(ctx, "")
	if err != nil {
		t.Fatalf("ListTLSRoutes failed: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 TLSRoute, got %d", len(routes))
	}
	if routes[0].Metadata.Name != "web-tls" {
		t.Errorf("expected TLSRoute 'web-tls', got %q", routes[0].Metadata.Name)
	}
}

func TestClientTLSRouteNotFoundFallback(t *testing.T) {
	mockTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"message": "not found"}`))),
			Header:     make(http.Header),
		}, nil
	})

	client, err := NewClient(ClientConfig{
		APIServerURL:          "https://mock-k8s.local",
		InsecureSkipTLSVerify: true,
		Transport:             mockTransport,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	routes, err := client.ListTLSRoutes(context.Background(), "")
	if err != nil {
		t.Fatalf("expected nil error on 404 CRD fallback, got: %v", err)
	}
	if routes != nil {
		t.Errorf("expected nil routes on 404 fallback, got %v", routes)
	}
}
