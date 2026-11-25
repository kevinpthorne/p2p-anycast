package k8s

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"p2p-anycast/pkg/origin/dialer"
	control "p2p-anycast/pkg/proto/control"
)

// BuilderOptions configures the Kubernetes service and TLSRoute configuration builder.
type BuilderOptions struct {
	AnnotationPrefix      string // Custom prefix (default: p2p-anycast.io and anycast.io)
	DefaultGatewayTarget  string // Fallback gateway target (e.g. cilium-gateway.kube-system.svc.cluster.local:443)
	AllowLocalhostTargets bool   // Allow explicit raw target annotations pointing to 127.0.0.1/localhost
}

// ValidateTargetEndpoint validates a backend target string produced from Kubernetes
// annotations to prevent Server-Side Request Forgery (SSRF) against the node host,
// Unix domain sockets, cloud metadata services (169.254.169.254), or Kubernetes control plane ports.
func ValidateTargetEndpoint(target string, allowLocalhost bool) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("empty target endpoint")
	}

	lower := strings.ToLower(target)
	if strings.HasPrefix(lower, "unix://") {
		return fmt.Errorf("unix domain socket targets (%q) are forbidden from Kubernetes annotations", target)
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target host:port %q: %w", target, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("invalid target port in %q", target)
	}

	// Block sensitive control-plane and host management ports (API server, etcd, kubelet)
	switch port {
	case 2379, 2380, 6443, 10250, 10255, 10257, 10259:
		return fmt.Errorf("target port %d in %q is reserved for cluster control plane", port, target)
	}

	hostLower := strings.ToLower(strings.TrimSpace(host))
	if hostLower == "" {
		return fmt.Errorf("empty target host in %q", target)
	}

	// Block Kubernetes default API service hostnames
	if hostLower == "kubernetes" ||
		hostLower == "kubernetes.default" ||
		strings.HasPrefix(hostLower, "kubernetes.default.") {
		return fmt.Errorf("target host %q is forbidden (Kubernetes API server)", host)
	}

	if hostLower == "localhost" || strings.HasSuffix(hostLower, ".localhost") {
		if !allowLocalhost {
			return fmt.Errorf("localhost target %q is not permitted via raw target annotation", target)
		}
		return nil
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("unspecified or multicast target IP %s is forbidden", ip.String())
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("link-local / cloud metadata target IP %s is forbidden", ip.String())
		}
		// Explicitly check 169.254.0.0/16 metadata range
		if ip4 := ip.To4(); ip4 != nil && ip4[0] == 169 && ip4[1] == 254 {
			return fmt.Errorf("cloud metadata range 169.254.0.0/16 (%s) is forbidden", ip.String())
		}
		if ip.IsLoopback() && !allowLocalhost {
			return fmt.Errorf("loopback target IP %s is not permitted via raw target annotation", ip.String())
		}
	}

	return nil
}

// BuildServicesFromK8s transforms Kubernetes Service and TLSRoute objects into dialer.ServiceConfig entries.
func BuildServicesFromK8s(services []Service, tlsRoutes []TLSRoute, opts BuilderOptions) []dialer.ServiceConfig {
	var results []dialer.ServiceConfig

	for _, svc := range services {
		configs := buildFromService(svc, opts)
		results = append(results, configs...)
	}

	for _, route := range tlsRoutes {
		configs := buildFromTLSRoute(route, opts)
		results = append(results, configs...)
	}

	return results
}

func getAnnotation(annotations map[string]string, key string, customPrefix string) string {
	if annotations == nil {
		return ""
	}

	// 1. Custom prefix if provided
	if customPrefix != "" {
		p := strings.TrimSuffix(customPrefix, "/")
		if val, ok := annotations[p+"/"+key]; ok {
			return strings.TrimSpace(val)
		}
	}

	// 2. Canonical p2p-anycast.io prefix
	if val, ok := annotations["p2p-anycast.io/"+key]; ok {
		return strings.TrimSpace(val)
	}

	// 3. Shorthand anycast.io prefix
	if val, ok := annotations["anycast.io/"+key]; ok {
		return strings.TrimSpace(val)
	}

	return ""
}

func isExposed(annotations map[string]string, customPrefix string) bool {
	val := strings.ToLower(getAnnotation(annotations, "expose", customPrefix))
	return val == "true" || val == "1" || val == "yes" || val == "on" || val == "enabled"
}

func parsePolicy(policyStr string) control.RoutingPolicy {
	switch strings.ToUpper(strings.TrimSpace(policyStr)) {
	case "CLUSTERED_RTT":
		return control.RoutingPolicy_CLUSTERED_RTT
	case "FAILOVER_STANDBY":
		return control.RoutingPolicy_FAILOVER_STANDBY
	case "STRICT_SINGLETON":
		return control.RoutingPolicy_STRICT_SINGLETON
	default:
		// Per specification, default to STRICT_SINGLETON
		return control.RoutingPolicy_STRICT_SINGLETON
	}
}

func parseProtocol(protoStr string, fallback string) control.TransportProtocol {
	p := strings.ToUpper(strings.TrimSpace(protoStr))
	if p == "" {
		p = strings.ToUpper(strings.TrimSpace(fallback))
	}
	switch p {
	case "UDP":
		return control.TransportProtocol_UDP
	case "TCP_AND_UDP":
		return control.TransportProtocol_TCP_AND_UDP
	case "TCP":
		fallthrough
	default:
		return control.TransportProtocol_TCP
	}
}

func parseBool(boolStr string) bool {
	val := strings.ToLower(strings.TrimSpace(boolStr))
	return val == "true" || val == "1" || val == "yes"
}

func sanitizeID(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, ".", "-"), "_", "-")
}

// parsePublicPorts rejects the whole annotation on malformed input rather than
// silently advertising a default or only part of the requested port list.
func parsePublicPorts(value string, fallback uint32) ([]uint32, error) {
	if value == "" {
		if fallback == 0 || fallback > 65535 {
			return nil, fmt.Errorf("invalid default public port %d", fallback)
		}
		return []uint32{fallback}, nil
	}
	ports := make([]uint32, 0, strings.Count(value, ",")+1)
	for token := range strings.SplitSeq(value, ",") {
		port, err := strconv.ParseUint(strings.TrimSpace(token), 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("invalid public port %q", token)
		}
		duplicate := false
		for _, existing := range ports {
			if existing == uint32(port) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			ports = append(ports, uint32(port))
		}
	}
	return ports, nil
}

func buildFromService(svc Service, opts BuilderOptions) []dialer.ServiceConfig {
	annos := svc.Metadata.Annotations
	if !isExposed(annos, opts.AnnotationPrefix) {
		return nil
	}

	ns := svc.Metadata.Namespace
	if ns == "" {
		ns = "default"
	}
	svcName := svc.Metadata.Name

	sniHostnames := getAnnotation(annos, "sni-hostnames", opts.AnnotationPrefix)
	sniHostname := getAnnotation(annos, "sni-hostname", opts.AnnotationPrefix)
	if sniHostnames != "" || sniHostname != "" {
		hostnames := []string{sniHostname}
		if sniHostnames != "" {
			hostnames = strings.Split(sniHostnames, ",")
		}
		publicPorts, err := parsePublicPorts(getAnnotation(annos, "public-port", opts.AnnotationPrefix), 443)
		if err != nil {
			log.Printf("[K8sBuilder] Rejecting service %s/%s: %v", ns, svcName, err)
			return nil
		}
		policy := parsePolicy(getAnnotation(annos, "policy", opts.AnnotationPrefix))
		enableProxy := parseBool(getAnnotation(annos, "enable-proxy-protocol", opts.AnnotationPrefix))
		baseID := getAnnotation(annos, "service-id", opts.AnnotationPrefix)
		if baseID == "" {
			baseID = svcName
		}
		out := make([]dialer.ServiceConfig, 0, len(hostnames)*len(publicPorts))
		for portIndex, publicPort := range publicPorts {
			portString := strconv.FormatUint(uint64(publicPort), 10)
			target := getAnnotation(annos, "target."+portString, opts.AnnotationPrefix)
			if target == "" {
				target = getAnnotation(annos, "target", opts.AnnotationPrefix)
			}
			if target == "" {
				if len(publicPorts) > 1 {
					// A port list selects matching TCP Service ports, not one shared gateway.
					matched := false
					for _, port := range svc.Spec.Ports {
						if uint32(port.Port) == publicPort && (port.Protocol == "" || port.Protocol == "TCP") {
							matched = true
							break
						}
					}
					if !matched {
						log.Printf("[K8sBuilder] Rejecting service %s/%s: public port %d has no matching TCP Service port or target override", ns, svcName, publicPort)
						return nil
					}
					target = svcName + "." + ns + ".svc.cluster.local:" + portString
				} else if sniHostnames == "" && opts.DefaultGatewayTarget != "" {
					target = opts.DefaultGatewayTarget
				} else {
					target = fmt.Sprintf("%s.%s.svc.cluster.local:443", svcName, ns)
				}
			}
			if err := ValidateTargetEndpoint(target, opts.AllowLocalhostTargets); err != nil {
				log.Printf("[K8sBuilder] Rejecting unsafe target for service %s/%s port %d: %v", ns, svcName, publicPort, err)
				return nil
			}
			hostIndex := 0
			for _, h := range hostnames {
				host := strings.TrimSpace(h)
				if host == "" {
					continue
				}
				sID := baseID
				if sniHostnames != "" {
					if portIndex == 0 {
						sID = fmt.Sprintf("%s-%s", baseID, sanitizeID(host))
					} else {
						// Service IDs are port-independent; reuse the first port's IDs.
						sID = out[hostIndex].ServiceID
					}
				}
				out = append(out, dialer.ServiceConfig{
					ServiceID:           sID,
					Protocol:            control.TransportProtocol_TCP,
					PublicPort:          publicPort,
					Policy:              policy,
					SNIHostname:         host,
					Target:              target,
					EnableProxyProtocol: enableProxy,
				})
				hostIndex++
			}
		}
		return out
	}

	// Case 3: Standard L4 Service (Minecraft, PBX, etc.)
	var out []dialer.ServiceConfig

	// Optional port filter
	var filterPorts map[string]bool
	if portsStr := getAnnotation(annos, "ports", opts.AnnotationPrefix); portsStr != "" {
		filterPorts = make(map[string]bool)
		for _, p := range strings.Split(portsStr, ",") {
			filterPorts[strings.TrimSpace(p)] = true
		}
	}

	multiplePorts := len(svc.Spec.Ports) > 1

	for _, port := range svc.Spec.Ports {
		portName := port.Name
		portNumStr := strconv.Itoa(int(port.Port))

		if filterPorts != nil {
			if !filterPorts[portName] && !filterPorts[portNumStr] {
				continue
			}
		}

		// Check per-port overrides
		perPortID := getAnnotation(annos, "service-id."+portName, opts.AnnotationPrefix)
		if perPortID == "" {
			perPortID = getAnnotation(annos, "service-id."+portNumStr, opts.AnnotationPrefix)
		}

		sID := perPortID
		if sID == "" {
			baseID := getAnnotation(annos, "service-id", opts.AnnotationPrefix)
			if baseID == "" {
				baseID = svcName
			}
			if multiplePorts {
				suffix := portName
				if suffix == "" {
					suffix = portNumStr
				}
				sID = fmt.Sprintf("%s-%s", baseID, suffix)
			} else {
				sID = baseID
			}
		}

		// Public port
		publicPort := uint32(port.Port)
		perPortPub := getAnnotation(annos, "public-port."+portName, opts.AnnotationPrefix)
		if perPortPub == "" {
			perPortPub = getAnnotation(annos, "public-port."+portNumStr, opts.AnnotationPrefix)
		}
		if perPortPub == "" {
			perPortPub = getAnnotation(annos, "public-port", opts.AnnotationPrefix)
		}
		if perPortPub != "" {
			if p, err := strconv.ParseUint(perPortPub, 10, 32); err == nil {
				publicPort = uint32(p)
			}
		}

		// Protocol
		perPortProto := getAnnotation(annos, "protocol."+portName, opts.AnnotationPrefix)
		if perPortProto == "" {
			perPortProto = getAnnotation(annos, "protocol."+portNumStr, opts.AnnotationPrefix)
		}
		if perPortProto == "" {
			perPortProto = getAnnotation(annos, "protocol", opts.AnnotationPrefix)
		}
		proto := parseProtocol(perPortProto, port.Protocol)

		// Policy
		perPortPolicy := getAnnotation(annos, "policy."+portName, opts.AnnotationPrefix)
		if perPortPolicy == "" {
			perPortPolicy = getAnnotation(annos, "policy."+portNumStr, opts.AnnotationPrefix)
		}
		if perPortPolicy == "" {
			perPortPolicy = getAnnotation(annos, "policy", opts.AnnotationPrefix)
		}
		policy := parsePolicy(perPortPolicy)

		// Target
		perPortTarget := getAnnotation(annos, "target."+portName, opts.AnnotationPrefix)
		if perPortTarget == "" {
			perPortTarget = getAnnotation(annos, "target."+portNumStr, opts.AnnotationPrefix)
		}
		if perPortTarget == "" {
			perPortTarget = getAnnotation(annos, "target", opts.AnnotationPrefix)
		}

		target := perPortTarget
		allowLocal := opts.AllowLocalhostTargets
		if target == "" {
			targetType := strings.ToLower(getAnnotation(annos, "target-type", opts.AnnotationPrefix))
			if (targetType == "cluster-ip" || targetType == "clusterip") && svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
				target = fmt.Sprintf("%s:%d", svc.Spec.ClusterIP, port.Port)
			} else if targetType == "localhost" || targetType == "pod" {
				target = fmt.Sprintf("127.0.0.1:%d", port.Port)
				allowLocal = true
			} else {
				target = fmt.Sprintf("%s.%s.svc.cluster.local:%d", svcName, ns, port.Port)
			}
		}
		if err := ValidateTargetEndpoint(target, allowLocal); err != nil {
			log.Printf("[K8sBuilder] Rejecting unsafe target for service %s/%s port %d: %v", ns, svcName, port.Port, err)
			continue
		}

		// Proxy Protocol
		perPortPP := getAnnotation(annos, "enable-proxy-protocol."+portName, opts.AnnotationPrefix)
		if perPortPP == "" {
			perPortPP = getAnnotation(annos, "enable-proxy-protocol", opts.AnnotationPrefix)
		}
		enableProxy := parseBool(perPortPP)

		out = append(out, dialer.ServiceConfig{
			ServiceID:           sID,
			Protocol:            proto,
			PublicPort:          publicPort,
			Policy:              policy,
			SNIHostname:         "",
			Target:              target,
			EnableProxyProtocol: enableProxy,
		})
	}

	return out
}

func buildFromTLSRoute(route TLSRoute, opts BuilderOptions) []dialer.ServiceConfig {
	annos := route.Metadata.Annotations
	if !isExposed(annos, opts.AnnotationPrefix) {
		return nil
	}

	ns := route.Metadata.Namespace
	if ns == "" {
		ns = "default"
	}
	routeName := route.Metadata.Name

	policy := parsePolicy(getAnnotation(annos, "policy", opts.AnnotationPrefix))
	enableProxy := parseBool(getAnnotation(annos, "enable-proxy-protocol", opts.AnnotationPrefix))

	// Determine public ports: annotation override -> parentRef port -> default 443.
	defaultPort := uint32(443)
	if len(route.Spec.ParentRefs) > 0 && route.Spec.ParentRefs[0].Port != nil {
		defaultPort = uint32(*route.Spec.ParentRefs[0].Port)
	}
	publicPorts, err := parsePublicPorts(getAnnotation(annos, "public-port", opts.AnnotationPrefix), defaultPort)
	if err != nil {
		log.Printf("[K8sBuilder] Rejecting TLSRoute %s/%s: %v", ns, routeName, err)
		return nil
	}

	// Determine target:
	// 1. Explicit annotation override
	// 2. Target backend if requested (p2p-anycast.io/target-backend: "true")
	// 3. Parent Gateway FQDN
	// 4. DefaultGatewayTarget fallback
	target := getAnnotation(annos, "target", opts.AnnotationPrefix)
	if target == "" {
		targetBackend := parseBool(getAnnotation(annos, "target-backend", opts.AnnotationPrefix))
		if targetBackend && len(route.Spec.Rules) > 0 && len(route.Spec.Rules[0].BackendRefs) > 0 {
			bRef := route.Spec.Rules[0].BackendRefs[0]
			bNs := ns
			if bRef.Namespace != nil && *bRef.Namespace != "" {
				bNs = *bRef.Namespace
			}
			bPort := 443
			if bRef.Port != nil {
				bPort = int(*bRef.Port)
			}
			target = fmt.Sprintf("%s.%s.svc.cluster.local:%d", bRef.Name, bNs, bPort)
		} else if len(route.Spec.ParentRefs) > 0 {
			pRef := route.Spec.ParentRefs[0]
			pNs := ns
			if pRef.Namespace != nil && *pRef.Namespace != "" {
				pNs = *pRef.Namespace
			}
			pPort := 443
			if pRef.Port != nil {
				pPort = int(*pRef.Port)
			}
			target = fmt.Sprintf("%s.%s.svc.cluster.local:%d", pRef.Name, pNs, pPort)
		} else if opts.DefaultGatewayTarget != "" {
			target = opts.DefaultGatewayTarget
		}
	}

	if err := ValidateTargetEndpoint(target, opts.AllowLocalhostTargets); err != nil {
		log.Printf("[K8sBuilder] Rejecting unsafe target for TLSRoute %s/%s: %v", ns, routeName, err)
		return nil
	}

	baseID := getAnnotation(annos, "service-id", opts.AnnotationPrefix)
	if baseID == "" {
		baseID = routeName
	}

	multipleHosts := len(route.Spec.Hostnames) > 1
	out := make([]dialer.ServiceConfig, 0, len(route.Spec.Hostnames)*len(publicPorts))

	for _, h := range route.Spec.Hostnames {
		hostname := strings.TrimSpace(h)
		if hostname == "" {
			continue
		}

		sID := baseID
		if multipleHosts {
			sID = fmt.Sprintf("%s-%s", baseID, sanitizeID(hostname))
		}

		for _, publicPort := range publicPorts {
			out = append(out, dialer.ServiceConfig{
				ServiceID:           sID,
				Protocol:            control.TransportProtocol_TCP,
				PublicPort:          publicPort,
				Policy:              policy,
				SNIHostname:         hostname,
				Target:              target,
				EnableProxyProtocol: enableProxy,
			})
		}
	}

	return out
}
