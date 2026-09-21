package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"p2p-anycast/pkg/pki/manifest"
	"p2p-anycast/pkg/pki/mldsa"
	identity "p2p-anycast/pkg/proto/identity"
)

type PolicyJSON struct {
	SerialNumber          uint64                   `json:"serial_number"`
	SubjectID             string                   `json:"subject_id"`
	Role                  string                   `json:"role"` // "EDGE_ROUTER" or "ORIGIN_NODE"
	Libp2PPeerID          string                   `json:"libp2p_peer_id"`
	SubjectMLDSAPubkeyFile string                  `json:"subject_mldsa_pubkey_file"`
	ValidityDays          int                      `json:"validity_days"`
	Capabilities          []ServiceCapabilityJSON  `json:"capabilities"`
}

type ServiceCapabilityJSON struct {
	ServicePattern  string          `json:"service_pattern"`
	AllowedPolicies []string        `json:"allowed_policies"`
	AllowedPorts    []PortRangeJSON `json:"allowed_ports"`
}

type PortRangeJSON struct {
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	switch subcommand {
	case "init":
		cmdInit(os.Args[2:])
	case "sign":
		cmdSign(os.Args[2:])
	case "inspect":
		cmdInspect(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: anycast-ca <subcommand> [flags]")
	fmt.Println("Subcommands:")
	fmt.Println("  init     Generate a new Root ML-DSA-87 keypair (ca.priv, ca.pub)")
	fmt.Println("  sign     Sign an IdentityClaims policy and generate manifest.pb")
	fmt.Println("  inspect  Inspect and verify a SignedCapabilityManifest (manifest.pb)")
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	outDir := fs.String("out-dir", ".", "Directory to write ca.priv and ca.pub")
	_ = fs.Parse(args)

	caPub, caPriv, err := mldsa.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating ML-DSA-87 keypair: %v\n", err)
		os.Exit(1)
	}

	privPath := filepath.Join(*outDir, "ca.priv")
	pubPath := filepath.Join(*outDir, "ca.pub")

	privPEM := mldsa.EncodePrivateKeyToPEM(caPriv)
	pubPEM := mldsa.EncodePublicKeyToPEM(caPub)

	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write ca.priv: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write ca.pub: %v\n", err)
		os.Exit(1)
	}

	keyID := manifest.ComputeKeyID(caPub)
	fmt.Printf("Successfully generated Root CA ML-DSA-87 keypair:\n")
	fmt.Printf("  Private Key: %s\n", privPath)
	fmt.Printf("  Public Key:  %s\n", pubPath)
	fmt.Printf("  CA Key ID:   %x\n", keyID)
}

func cmdSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	caPrivPath := fs.String("ca-priv", "ca.priv", "Path to ca.priv")
	caPubPath := fs.String("ca-pub", "ca.pub", "Path to ca.pub")
	policyPath := fs.String("policy", "policy.json", "Path to policy JSON file")
	outFile := fs.String("out", "manifest.pb", "Path to output manifest.pb")
	_ = fs.Parse(args)

	// Load CA Private Key
	privBytes, err := os.ReadFile(*caPrivPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading ca.priv: %v\n", err)
		os.Exit(1)
	}
	caPriv, err := mldsa.DecodePrivateKeyFromPEM(privBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing ca.priv: %v\n", err)
		os.Exit(1)
	}

	// Load CA Public Key
	pubBytes, err := os.ReadFile(*caPubPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading ca.pub: %v\n", err)
		os.Exit(1)
	}
	caPub, err := mldsa.DecodePublicKeyFromPEM(pubBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing ca.pub: %v\n", err)
		os.Exit(1)
	}

	// Read Policy JSON
	policyData, err := os.ReadFile(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading policy file: %v\n", err)
		os.Exit(1)
	}

	var pol PolicyJSON
	if err := json.Unmarshal(policyData, &pol); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing policy JSON: %v\n", err)
		os.Exit(1)
	}

	// Load Subject Public Key
	subPubBytes, err := os.ReadFile(pol.SubjectMLDSAPubkeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading subject public key %s: %v\n", pol.SubjectMLDSAPubkeyFile, err)
		os.Exit(1)
	}
	subPub, err := mldsa.DecodePublicKeyFromPEM(subPubBytes)
	if err != nil {
		// Try raw bytes if not PEM
		subPub, err = mldsa.PublicKeyFromBytes(subPubBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding subject public key: %v\n", err)
			os.Exit(1)
		}
	}

	role := identity.NodeRole_ORIGIN_NODE
	if strings.EqualFold(pol.Role, "EDGE_ROUTER") {
		role = identity.NodeRole_EDGE_ROUTER
	}

	validityDays := pol.ValidityDays
	if validityDays <= 0 {
		validityDays = 365
	}
	now := time.Now()

	claims := &identity.IdentityClaims{
		SerialNumber:       pol.SerialNumber,
		IssuerId:           "MeshCast Root CA",
		SubjectId:          pol.SubjectID,
		Role:               role,
		SubjectMldsaPubkey: mldsa.PublicKeyToBytes(subPub),
		Libp2PPeerId:       pol.Libp2PPeerID,
		NotBefore:          now.Add(-1 * time.Hour).Unix(),
		NotAfter:           now.Add(time.Duration(validityDays) * 24 * time.Hour).Unix(),
	}

	for _, capJSON := range pol.Capabilities {
		cap := &identity.ServiceCapability{
			ServicePattern: capJSON.ServicePattern,
		}
		for _, p := range capJSON.AllowedPolicies {
			switch strings.ToUpper(p) {
			case "CLUSTERED_RTT", "POLICY_CLUSTERED_RTT":
				cap.AllowedPolicies = append(cap.AllowedPolicies, identity.AuthorizedPolicy_POLICY_CLUSTERED_RTT)
			case "TLS_SNI", "POLICY_TLS_SNI":
				cap.AllowedPolicies = append(cap.AllowedPolicies, identity.AuthorizedPolicy_POLICY_TLS_SNI)
			case "FAILOVER_STANDBY", "POLICY_FAILOVER_STANDBY":
				cap.AllowedPolicies = append(cap.AllowedPolicies, identity.AuthorizedPolicy_POLICY_FAILOVER_STANDBY)
			case "STRICT_SINGLETON", "POLICY_STRICT_SINGLETON":
				cap.AllowedPolicies = append(cap.AllowedPolicies, identity.AuthorizedPolicy_POLICY_STRICT_SINGLETON)
			}
		}
		for _, pr := range capJSON.AllowedPorts {
			cap.AllowedPorts = append(cap.AllowedPorts, &identity.PortRange{
				Start: pr.Start,
				End:   pr.End,
			})
		}
		claims.Capabilities = append(claims.Capabilities, cap)
	}

	signedManifest, err := manifest.SignManifest(claims, caPriv, caPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing manifest: %v\n", err)
		os.Exit(1)
	}

	manifestBytes, err := proto.Marshal(signedManifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling signed manifest: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outFile, manifestBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", *outFile, err)
		os.Exit(1)
	}

	fmt.Printf("Successfully generated signed manifest: %s\n", *outFile)
	fmt.Printf("  Subject ID: %s (%v)\n", claims.SubjectId, claims.Role)
	fmt.Printf("  Peer ID:    %s\n", claims.Libp2PPeerId)
	fmt.Printf("  Valid:      %s to %s\n", time.Unix(claims.NotBefore, 0), time.Unix(claims.NotAfter, 0))
}

func cmdInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	manifestPath := fs.String("manifest", "manifest.pb", "Path to manifest.pb")
	caPubPath := fs.String("ca-pub", "", "Optional path to trusted ca.pub to verify signature")
	_ = fs.Parse(args)

	manifestData, err := os.ReadFile(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading manifest file: %v\n", err)
		os.Exit(1)
	}

	var signedManifest identity.SignedCapabilityManifest
	if err := proto.Unmarshal(manifestData, &signedManifest); err != nil {
		fmt.Fprintf(os.Stderr, "Error unmarshaling manifest: %v\n", err)
		os.Exit(1)
	}

	var claims identity.IdentityClaims
	if err := proto.Unmarshal(signedManifest.ClaimsPayload, &claims); err != nil {
		fmt.Fprintf(os.Stderr, "Error unmarshaling claims payload: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Capability Manifest ===")
	fmt.Printf("Serial Number:  %d\n", claims.SerialNumber)
	fmt.Printf("Issuer ID:      %s\n", claims.IssuerId)
	fmt.Printf("Subject ID:     %s\n", claims.SubjectId)
	fmt.Printf("Role:           %v\n", claims.Role)
	fmt.Printf("Libp2p Peer ID: %s\n", claims.Libp2PPeerId)
	fmt.Printf("Not Before:     %s\n", time.Unix(claims.NotBefore, 0))
	fmt.Printf("Not After:      %s\n", time.Unix(claims.NotAfter, 0))
	fmt.Printf("CA Key ID:      %x\n", signedManifest.CaKeyId)
	fmt.Printf("Capabilities:   %d declared\n", len(claims.Capabilities))

	for i, cap := range claims.Capabilities {
		fmt.Printf("  [%d] Service Pattern: %q\n", i+1, cap.ServicePattern)
		fmt.Printf("      Policies:         %v\n", cap.AllowedPolicies)
		for _, pr := range cap.AllowedPorts {
			fmt.Printf("      Port Range:       %d - %d\n", pr.Start, pr.End)
		}
	}

	if *caPubPath != "" {
		caPubBytes, err := os.ReadFile(*caPubPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading ca.pub: %v\n", err)
			os.Exit(1)
		}
		caPub, err := mldsa.DecodePublicKeyFromPEM(caPubBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing ca.pub: %v\n", err)
			os.Exit(1)
		}

		verifiedClaims, err := manifest.VerifyManifest(&signedManifest, caPub)
		if err != nil {
			fmt.Printf("\n[SIGNATURE VERIFICATION FAILED]: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n[SIGNATURE VALID]: Successfully verified by trusted Root CA for subject %q\n", verifiedClaims.SubjectId)
	}
}
