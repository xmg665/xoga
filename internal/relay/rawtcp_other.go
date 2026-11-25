//go:build !unix

package relay

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/xmg665/xoga/internal/limiter"
	"github.com/xmg665/xoga/internal/stats"
)

func tryCopyFromRawTCP(
	_ net.Conn,
	_ *net.TCPConn,
	_ int,
	_ *stats.UserEntry,
	_ *limiter.Bucket,
	_ bool,
	_ time.Duration,
	_ *atomic.Bool,
) bool {
	return false
}
