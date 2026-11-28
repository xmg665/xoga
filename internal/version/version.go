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
	ver := strings.TrimPrefix(strings.TrimSpace(Version), "v")
	return "xoga v" + ver + " (" + runtime.GOOS + "/" + runtime.GOARCH + ", " + runtime.Version() + ", commit " + Commit + ")"
}
