package version

import (
	"strings"
	"testing"
)

func TestVersionInfo(t *testing.T) {
	v := Info()
	if !strings.HasPrefix(v, "v1.0.1") {
		t.Fatalf("expected version string to start with v1.0.1, got: %s", v)
	}
}
