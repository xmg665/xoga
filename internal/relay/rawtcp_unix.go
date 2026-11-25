//go:build unix

package relay

import (
	"net"
	"syscall"
	"time"

	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/limiter"
	"github.com/xmg665/xoga/internal/stats"
)

func tryCopyFromRawTCP(
	dst net.Conn,
	srcTCP *net.TCPConn,
	slabSize int,
	user *stats.UserEntry,
	nodeLim *limiter.Bucket,
	isUpload bool,
	idleTimeout time.Duration,
) bool {
	rawConn, err := srcTCP.SyscallConn()
	if err != nil {
		return false
	}

	var bp *[]byte
	defer func() {
		if bp != nil {
			bufpool.Put(bp)
		}
	}()

	for {
		_ = srcTCP.SetReadDeadline(time.Now().Add(idleTimeout))
		var nr int
		var readErr error
		var eof bool

		rerr := rawConn.Read(func(fd uintptr) bool {
			if bp == nil {
				bp = bufpool.Get(slabSize)
			}
			for {
				n, err := syscall.Read(int(fd), *bp)
				if n > 0 {
					nr = n
					return true
				}
				if err == nil {
					eof = true
					return true
				}
				if err == syscall.EINTR {
					continue
				}
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
					// Socket buffer is empty -> release slab BEFORE Go parks goroutine in epoll_wait!
					bufpool.Put(bp)
					bp = nil
					return false
				}
				readErr = err
				return true
			}
		})

		if nr > 0 {
			if user != nil {
				if ul := user.EffectiveLimiter(); ul != nil {
					ul.Wait(nr)
				}
				if isUpload {
					user.AddUpload(int64(nr))
				} else {
					user.AddDownload(int64(nr))
				}
			}
			if nodeLim != nil {
				nodeLim.Wait(nr)
			}

			_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
			nw, werr := writeFull(dst, (*bp)[:nr])
			if nr < slabSize {
				bufpool.Put(bp)
				bp = nil
			}
			if werr != nil || nw != nr {
				return true
			}
		}
		if eof || readErr != nil || rerr != nil {
			return true
		}
	}
}
