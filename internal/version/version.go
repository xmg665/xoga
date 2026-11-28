package version

import (
	"runtime"
	"strings"
)

var (
	Version   = "1.3.6"
	Commit    = "HEAD"
	BuildTime = "unknown"
)

func Summary() string {
	ver := strings.TrimLeft(strings.TrimSpace(Version), "vV")
	return "xoga v" + ver + " (" + runtime.GOOS + "/" + runtime.GOARCH + ", " + runtime.Version() + ", commit " + Commit + ")"
}
