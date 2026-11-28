//go:build unix

package relay

import (
	"errors"
	"net"
	"sync/atomic"
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
	abortPeer *atomic.Bool,
	peerDone *atomic.Bool,
	lastActive *atomic.Int64,
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
		if (user != nil && user.IsDisabled()) || (abortPeer != nil && abortPeer.Load()) {
			return true
		}
		effIdle := effectiveIdle(idleTimeout, peerDone)
		_ = srcTCP.SetReadDeadline(time.Now().Add(effIdle))
		if abortPeer != nil && abortPeer.Load() {
			_ = srcTCP.SetReadDeadline(time.Now())
			return true
		}
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
			if lastActive != nil {
				lastActive.Store(time.Now().UnixNano())
			}
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
			if nw > 0 && lastActive != nil {
				lastActive.Store(time.Now().UnixNano())
			}
			if nr < slabSize {
				bufpool.Put(bp)
				bp = nil
			}
			if werr != nil || nw != nr {
				return true
			}
		}
		if eof || readErr != nil {
			return true
		}
		if rerr != nil {
			if isNetTimeout(rerr) && !(user != nil && user.IsDisabled()) && !(abortPeer != nil && abortPeer.Load()) {
				if isStreamStillActive(lastActive, effectiveIdle(idleTimeout, peerDone)) {
					continue
				}
			}
			return true
		}
	}
}

// ReadPacketZeroIdle reads one UDP datagram without holding a 64 KiB `bufpool` buffer while parked in epoll!
// On EAGAIN/EWOULDBLOCK, `bp` is immediately returned to `bufpool` before Go's netpoller suspends the goroutine.
func ReadPacketZeroIdle(pc net.PacketConn) (int, net.Addr, []byte, *[]byte, error) {
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		bp := bufpool.Get(bufpool.MaxUDPSize)
		buf := *bp
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || addr == nil {
			bufpool.Put(bp)
			if err == nil {
				err = errors.New("udp readfrom: nil source address")
			}
			return 0, nil, nil, nil, err
		}
		return n, addr, buf, bp, nil
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		bp := bufpool.Get(bufpool.MaxUDPSize)
		buf := *bp
		n, addr, rerr := pc.ReadFrom(buf)
		if rerr != nil || addr == nil {
			bufpool.Put(bp)
			if rerr == nil {
				rerr = errors.New("udp readfrom: nil source address")
			}
			return 0, nil, nil, nil, rerr
		}
		return n, addr, buf, bp, nil
	}

	var bp *[]byte
	var nr int
	var raddr net.Addr
	var recvErr error

	err = rc.Read(func(fd uintptr) bool {
		if bp == nil {
			bp = bufpool.Get(bufpool.MaxUDPSize)
		}
		for {
			n, sa, serr := syscall.Recvfrom(int(fd), *bp, 0)
			if serr == syscall.EINTR {
				continue
			}
			if serr == syscall.EAGAIN || serr == syscall.EWOULDBLOCK {
				bufpool.Put(bp)
				bp = nil
				return false
			}
			if serr != nil {
				recvErr = serr
				return true
			}
			nr = n
			switch a := sa.(type) {
			case *syscall.SockaddrInet4:
				ip := make(net.IP, 4)
				copy(ip, a.Addr[:])
				raddr = &net.UDPAddr{IP: ip, Port: a.Port}
			case *syscall.SockaddrInet6:
				ip := make(net.IP, 16)
				copy(ip, a.Addr[:])
				raddr = &net.UDPAddr{IP: ip, Port: a.Port}
			}
			return true
		}
	})
	if err != nil || recvErr != nil || raddr == nil {
		if bp != nil {
			bufpool.Put(bp)
		}
		if recvErr != nil {
			return 0, nil, nil, nil, recvErr
		}
		if err != nil {
			return 0, nil, nil, nil, err
		}
		return 0, nil, nil, nil, errors.New("udp recvfrom: nil or unsupported source address")
	}
	return nr, raddr, *bp, bp, nil
}

func isNoRouteOrUnreachable(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.EADDRNOTAVAIL) ||
		errors.Is(err, syscall.EAFNOSUPPORT)
}
