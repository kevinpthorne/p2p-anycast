package firewall

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Protocol represents the transport protocol (tcp or udp).
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// Manager manages dynamic firewall rules for open ingress ports.
type Manager interface {
	// OpenPort opens a public ingress port for the specified protocol.
	OpenPort(proto Protocol, port uint16) error

	// ClosePort closes a public ingress port for the specified protocol.
	ClosePort(proto Protocol, port uint16) error

	// Close cleans up all firewall rules and chains created by this manager.
	Close() error
}

// commandRunner executes an external shell command.
type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

func defaultCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

// New creates a new firewall Manager based on the requested backend.
// Valid backends: "auto", "iptables", "nftables", "none", "noop".
func New(backend string) (Manager, error) {
	b := strings.ToLower(strings.TrimSpace(backend))
	if b == "" || b == "auto" {
		return newAutoManager(defaultCommandRunner)
	}

	switch b {
	case "none", "noop", "disabled":
		return NewNoopManager(), nil
	case "iptables":
		return newIptablesManager(defaultCommandRunner)
	case "nftables":
		return newNftablesManager(defaultCommandRunner)
	default:
		return nil, fmt.Errorf("unsupported firewall backend: %q (valid: auto, iptables, nftables, none)", backend)
	}
}

// newAutoManager detects the available firewall utility on the host.
func newAutoManager(runner commandRunner) (Manager, error) {
	if runtime.GOOS != "linux" {
		log.Printf("[Firewall] OS is %s (not linux); using no-op firewall manager", runtime.GOOS)
		return NewNoopManager(), nil
	}

	// 1. Check if nftables is active and nixos-fw table is present
	if _, err := exec.LookPath("nft"); err == nil {
		out, err := runner(context.Background(), "nft", "list", "table", "inet", "nixos-fw")
		if err == nil && len(out) > 0 {
			log.Printf("[Firewall] Detected NixOS nftables ruleset (inet nixos-fw); using nftables backend")
			return newNftablesManagerWithTable(runner, "nixos-fw")
		}
	}

	// 2. Check if iptables is present
	if _, err := exec.LookPath("iptables"); err == nil {
		log.Printf("[Firewall] Detected iptables; using iptables backend")
		return newIptablesManager(runner)
	}

	// 3. Fallback to nftables if nft exists
	if _, err := exec.LookPath("nft"); err == nil {
		log.Printf("[Firewall] Detected nft; using nftables backend")
		return newNftablesManager(runner)
	}

	// 4. Fallback to noop with a warning
	log.Printf("[Firewall] WARNING: Neither iptables nor nftables found in PATH. Dynamic firewall port management disabled.")
	return NewNoopManager(), nil
}

func init() {
	// Set XTABLES_LOCKFILE default if not already set, avoiding permission errors on /run/xtables.lock for dynamic users
	if os.Getenv("XTABLES_LOCKFILE") == "" {
		if os.Getenv("RUNTIME_DIRECTORY") != "" {
			_ = os.Setenv("XTABLES_LOCKFILE", os.Getenv("RUNTIME_DIRECTORY")+"/xtables.lock")
		} else {
			_ = os.Setenv("XTABLES_LOCKFILE", "/tmp/xtables.lock")
		}
	}
}
