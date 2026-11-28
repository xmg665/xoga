//go:build !unix

package relay

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/xmg665/xoga/internal/bufpool"
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
	_ *atomic.Bool,
	_ *atomic.Int64,
) bool {
	return false
}

func ReadPacketZeroIdle(pc net.PacketConn) (int, net.Addr, []byte, *[]byte, error) {
	bp := bufpool.Get(bufpool.MaxUDPSize)
	buf := *bp
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		bufpool.Put(bp)
		return 0, nil, nil, nil, err
	}
	return n, addr, buf, bp, nil
}
