package version

import "runtime"

var (
	Version   = "1.2.1"
	Commit    = "HEAD"
	BuildTime = "unknown"
)

func Summary() string {
	return "xoga v" + Version + " (" + runtime.GOOS + "/" + runtime.GOARCH + ", " + runtime.Version() + ", commit " + Commit + ")"
}
