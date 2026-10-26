package version

import (
	"fmt"
	"runtime/debug"
)

// Version is the semantic release version.
// It can be overridden at link time via:
//
//	-ldflags "-X p2p-anycast/pkg/version.Version=v1.0.1"
var Version = "1.0.1"

// Info returns a human-readable version string including VCS revision and dirty state if available.
// Examples:
//
//	"v1.0.1 (7bde845)"
//	"v1.0.1 (7bde845-dirty)"
//	"v1.0.1"
func Info() string {
	revision, modified := "", false
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if len(s.Value) >= 7 {
					revision = s.Value[:7]
				} else {
					revision = s.Value
				}
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
	}

	prefix := ""
	if len(Version) > 0 && Version[0] != 'v' {
		prefix = "v"
	}

	if revision != "" {
		if modified {
			return fmt.Sprintf("%s%s (%s-dirty)", prefix, Version, revision)
		}
		return fmt.Sprintf("%s%s (%s)", prefix, Version, revision)
	}
	return prefix + Version
}
