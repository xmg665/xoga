package version

import (
	"strings"
	"testing"
)

func TestSummaryNoDoubleVPrefix(t *testing.T) {
	orig := Version
	defer func() { Version = orig }()

	Version = "1.3.6"
	if s := Summary(); !strings.HasPrefix(s, "xoga v1.3.6 ") || strings.Contains(s, "vv") {
		t.Fatalf("unexpected Summary for bare version: %q", s)
	}
	Version = "v1.3.6"
	if s := Summary(); !strings.HasPrefix(s, "xoga v1.3.6 ") || strings.Contains(s, "vv") {
		t.Fatalf("Summary produced double-v prefix: %q", s)
	}
}
