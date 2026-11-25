package relay

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/limiter"
	"github.com/xmg665/xoga/internal/stats"
)

const spliceChunkSize = 4 * 1024 * 1024 // 4 MiB kernel splice window for live traffic accounting

// PipeBidirectional relays data between clientConn and remoteConn with:
// 1. Linux kernel splice(2) zero-copy fast-path when both ends are raw *net.TCPConn and unthrottled.
// 2. Pooled 32 KiB slab buffers (zero heap allocs per stream) for TLS/AEAD/WS or rate-limited streams.
// 3. Half-close propagation and idle timeout enforcement to prevent goroutine/FD leaks.
func PipeBidirectional(
	clientConn net.Conn,
	remoteConn net.Conn,
	initialClientPayload []byte,
	user *stats.UserEntry,
	nodeLim *limiter.Bucket,
	idleTimeout time.Duration,
	enableZeroCopy bool,
) {
	TuneTCP(clientConn)
	TuneTCP(remoteConn)

	if len(initialClientPayload) > 0 {
		if user != nil {
			if ul := user.EffectiveLimiter(); ul != nil {
				ul.Wait(len(initialClientPayload))
			}
			user.AddUpload(int64(len(initialClientPayload)))
		}
		if nodeLim != nil {
			nodeLim.Wait(len(initialClientPayload))
		}
		_ = remoteConn.SetWriteDeadline(time.Now().Add(idleTimeout))
		if _, err := remoteConn.Write(initialClientPayload); err != nil {
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Upload: client -> remote
	go func() {
		defer wg.Done()
		copyOneWay(remoteConn, clientConn, user, nodeLim, true, idleTimeout, enableZeroCopy)
		closeWrite(remoteConn)
	}()

	// Download: remote -> client
	go func() {
		defer wg.Done()
		copyOneWay(clientConn, remoteConn, user, nodeLim, false, idleTimeout, enableZeroCopy)
		closeWrite(clientConn)
	}()

	wg.Wait()
}

func copyOneWay(
	dst net.Conn,
	src net.Conn,
	user *stats.UserEntry,
	nodeLim *limiter.Bucket,
	isUpload bool,
	idleTimeout time.Duration,
	enableZeroCopy bool,
) {
	var userLim *limiter.Bucket
	if user != nil {
		userLim = user.EffectiveLimiter()
	}

	// Fast-path: kernel splice(2) on Linux when both ends are raw *net.TCPConn and no token-bucket throttle is active.
	if enableZeroCopy && userLim == nil && nodeLim.IsUnlimited() {
		if dstTCP, ok1 := unwrapTCP(dst); ok1 {
			if srcTCP, ok2 := unwrapTCP(src); ok2 {
				for {
					now := time.Now()
					_ = srcTCP.SetReadDeadline(now.Add(idleTimeout))
					_ = dstTCP.SetWriteDeadline(now.Add(idleTimeout))
					n, err := io.CopyN(dstTCP, srcTCP, spliceChunkSize)
					if n > 0 && user != nil {
						if isUpload {
							user.AddUpload(n)
						} else {
							user.AddDownload(n)
						}
					}
					if err != nil {
						return
					}
				}
			}
		}
	}

	// Pooled 32 KiB slab buffer path (zero heap allocation per stream)
	bp := bufpool.Get(bufpool.LargeSize)
	buf := *bp
	defer bufpool.Put(bp)

	for {
		_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
		nr, rerr := src.Read(buf)
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
			nw, werr := writeFull(dst, buf[:nr])
			if werr != nil || nw != nr {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}

func writeFull(w io.Writer, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := w.Write(b[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func TuneTCP(c net.Conn) {
	if tc, ok := unwrapTCP(c); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(45 * time.Second)
	}
}

func unwrapTCP(c net.Conn) (*net.TCPConn, bool) {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc, true
	}
	return nil, false
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.SetReadDeadline(time.Now())
}

// PrependConn wraps a net.Conn when bytes have already been buffered/peeked during handshake or sniffing.
type PrependConn struct {
	net.Conn
	Reader io.Reader
}

func (p *PrependConn) Read(b []byte) (int, error) {
	return p.Reader.Read(b)
}

// ExtractClientIP parses a netip.Addr from a net.Addr without allocating strings when possible.
func ExtractClientIP(addr net.Addr) netip.Addr {
	if addr == nil {
		return netip.Addr{}
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			return ip.Unmap()
		}
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			return ip.Unmap()
		}
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip, _ := netip.ParseAddr(host)
	return ip.Unmap()
}
