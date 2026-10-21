package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultInClusterTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultInClusterCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultInClusterNSPath    = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// ClientConfig configures the Kubernetes API client.
type ClientConfig struct {
	APIServerURL           string
	Token                  string
	TokenFile              string
	CACertFile             string
	InsecureSkipTLSVerify  bool
	Namespace              string
	Timeout                time.Duration
	Transport              http.RoundTripper
}

// Client interacts with the Kubernetes REST API using native Go standard library.
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
	tokenFile  string
	namespace  string
}

// NewClient creates a new Kubernetes API client, automatically detecting in-cluster
// configuration if parameters are omitted.
func NewClient(cfg ClientConfig) (*Client, error) {
	baseURL := strings.TrimRight(cfg.APIServerURL, "/")
	if baseURL == "" {
		host := os.Getenv("KUBERNETES_SERVICE_HOST")
		port := os.Getenv("KUBERNETES_SERVICE_PORT")
		if host != "" && port != "" {
			baseURL = fmt.Sprintf("https://%s", net.JoinHostPort(host, port))
		}
	}
	if baseURL == "" {
		return nil, errors.New("kubernetes API server URL not configured and not running in-cluster")
	}

	token := cfg.Token
	tokenFile := cfg.TokenFile
	if token == "" && tokenFile == "" {
		if _, err := os.Stat(defaultInClusterTokenPath); err == nil {
			tokenFile = defaultInClusterTokenPath
		}
	}

	if token == "" && tokenFile != "" {
		data, err := os.ReadFile(tokenFile)
		if err == nil {
			token = strings.TrimSpace(string(data))
		}
	}

	caCertFile := cfg.CACertFile
	if caCertFile == "" {
		if _, err := os.Stat(defaultInClusterCAPath); err == nil {
			caCertFile = defaultInClusterCAPath
		}
	}

	if cfg.InsecureSkipTLSVerify {
		log.Printf("[K8sClient] WARNING: InsecureSkipTLSVerify is enabled for Kubernetes API server %s; TLS certificate verification is disabled!", baseURL)
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipTLSVerify,
	}

	if !cfg.InsecureSkipTLSVerify && caCertFile != "" {
		caData, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate %s: %w", caCertFile, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caCertFile)
		}
		tlsConfig.RootCAs = pool
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	transport := cfg.Transport
	if transport == nil {
		transport = &http.Transport{
			TLSClientConfig: tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
		}
	}

	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	ns := cfg.Namespace
	if ns == "" {
		if data, err := os.ReadFile(defaultInClusterNSPath); err == nil {
			ns = strings.TrimSpace(string(data))
		}
	}

	return &Client{
		httpClient: httpClient,
		baseURL:    baseURL,
		token:      token,
		tokenFile:  tokenFile,
		namespace:  ns,
	}, nil
}

func (c *Client) getToken() string {
	if c.tokenFile != "" {
		if data, err := os.ReadFile(c.tokenFile); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return c.token
}

func (c *Client) doRequest(ctx context.Context, method, path string) ([]byte, int, error) {
	url := fmt.Sprintf("%s%s", c.baseURL, path)
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, 0, err
	}

	token := c.getToken()
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return body, resp.StatusCode, nil
}

// ListServices queries Kubernetes for Service objects in the specified namespace,
// or across all namespaces if namespace is empty.
func (c *Client) ListServices(ctx context.Context, namespace string) ([]Service, error) {
	path := "/api/v1/services"
	if namespace != "" {
		path = fmt.Sprintf("/api/v1/namespaces/%s/services", namespace)
	}

	body, statusCode, err := c.doRequest(ctx, http.MethodGet, path)
	if err != nil {
		return nil, fmt.Errorf("failed to query services from %s: %w", path, err)
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list services (status %d): %s", statusCode, string(body))
	}

	var list ServiceList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("failed to decode ServiceList JSON: %w", err)
	}

	return list.Items, nil
}

// ListTLSRoutes queries Kubernetes for Gateway API TLSRoute objects in the specified namespace,
// or across all namespaces if namespace is empty. If the TLSRoute CRD is not present (404),
// it returns nil without error.
func (c *Client) ListTLSRoutes(ctx context.Context, namespace string) ([]TLSRoute, error) {
	apiPaths := []string{
		"/apis/gateway.networking.k8s.io/v1",
		"/apis/gateway.networking.k8s.io/v1alpha2",
	}

	for _, groupPath := range apiPaths {
		path := fmt.Sprintf("%s/tlsroutes", groupPath)
		if namespace != "" {
			path = fmt.Sprintf("%s/namespaces/%s/tlsroutes", groupPath, namespace)
		}

		body, statusCode, err := c.doRequest(ctx, http.MethodGet, path)
		if err != nil {
			return nil, fmt.Errorf("failed to query TLSRoutes from %s: %w", path, err)
		}

		if statusCode == http.StatusNotFound {
			// Try the next version or gracefully return nil if CRD not installed
			continue
		}

		if statusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to list TLSRoutes (status %d): %s", statusCode, string(body))
		}

		var list TLSRouteList
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, fmt.Errorf("failed to decode TLSRouteList JSON: %w", err)
		}

		return list.Items, nil
	}

	// Gateway API TLSRoute CRD is not installed on this cluster
	return nil, nil
}
