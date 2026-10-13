package k8s

import "encoding/json"

// ServiceList represents a Kubernetes v1.ServiceList response.
type ServiceList struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Items      []Service `json:"items"`
}

// Service represents a Kubernetes v1.Service object.
type Service struct {
	Metadata ObjectMeta  `json:"metadata"`
	Spec     ServiceSpec `json:"spec"`
}

// ObjectMeta contains standard Kubernetes object metadata.
type ObjectMeta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Annotations map[string]string `json:"annotations"`
	Labels      map[string]string `json:"labels"`
}

// ServiceSpec represents the spec of a Kubernetes Service.
type ServiceSpec struct {
	ClusterIP string        `json:"clusterIP"`
	Type      string        `json:"type"`
	Ports     []ServicePort `json:"ports"`
}

// ServicePort represents a port exposed by a Kubernetes Service.
type ServicePort struct {
	Name        string          `json:"name"`
	Protocol    string          `json:"protocol"` // "TCP", "UDP", "SCTP"
	Port        int32           `json:"port"`
	TargetPort  json.RawMessage `json:"targetPort"`
	NodePort    int32           `json:"nodePort"`
}

// TLSRouteList represents a Gateway API TLSRouteList response.
type TLSRouteList struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Items      []TLSRoute `json:"items"`
}

// TLSRoute represents a Gateway API TLSRoute object.
type TLSRoute struct {
	Metadata ObjectMeta   `json:"metadata"`
	Spec     TLSRouteSpec `json:"spec"`
}

// TLSRouteSpec defines the desired state of a TLSRoute.
type TLSRouteSpec struct {
	ParentRefs []ParentReference `json:"parentRefs"`
	Hostnames  []string          `json:"hostnames"`
	Rules      []TLSRouteRule    `json:"rules"`
}

// ParentReference identifies an API object to route through (e.g. Gateway).
type ParentReference struct {
	Group       *string `json:"group,omitempty"`
	Kind        *string `json:"kind,omitempty"`
	Namespace   *string `json:"namespace,omitempty"`
	Name        string  `json:"name"`
	SectionName *string `json:"sectionName,omitempty"`
	Port        *int32  `json:"port,omitempty"`
}

// TLSRouteRule defines semantics for attaching backends to a TLSRoute.
type TLSRouteRule struct {
	BackendRefs []BackendRef `json:"backendRefs"`
}

// BackendRef defines how a TLSRoute forwards traffic to a backend service.
type BackendRef struct {
	Group     *string `json:"group,omitempty"`
	Kind      *string `json:"kind,omitempty"`
	Namespace *string `json:"namespace,omitempty"`
	Name      string  `json:"name"`
	Port      *int32  `json:"port,omitempty"`
	Weight    *int32  `json:"weight,omitempty"`
}
