package version

import "runtime"

var (
	Version   = "1.0.0"
	Commit    = "HEAD"
	BuildTime = "unknown"
)

func Summary() string {
	return "xoga v" + Version + " (" + runtime.GOOS + "/" + runtime.GOARCH + ", " + runtime.Version() + ", commit " + Commit + ")"
}
