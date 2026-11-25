package relay

import (
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/limiter"
	"github.com/xmg665/xoga/internal/stats"
)

const spliceChunkSize = 4 * 1024 * 1024 // 4 MiB kernel splice window for live traffic accounting

// PipeBidirectional relays data between clientConn and remoteConn with:
// 1. Linux kernel splice(2) zero-copy fast-path when both ends are raw *net.TCPConn and unthrottled.
// 2. Zero-buffer idle epoll polling on *net.TCPConn (`copyFromRawTCP`) so thousands of idle streams hold 0 B of heap.
// 3. 2 goroutines per stream instead of 3 (download runs inline on caller goroutine, cutting goroutine count & stack RAM by 33%).
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

	uploadDone := make(chan struct{})

	// Upload: client -> remote (1 child goroutine)
	go func() {
		defer close(uploadDone)
		copyOneWay(remoteConn, clientConn, user, nodeLim, true, idleTimeout, enableZeroCopy)
		closeWrite(remoteConn)
	}()

	// Download: remote -> client (inline on current goroutine -> eliminates 1 goroutine + 4-8 KiB stack per connection!)
	copyOneWay(clientConn, remoteConn, user, nodeLim, false, idleTimeout, enableZeroCopy)
	closeWrite(clientConn)

	<-uploadDone
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

	srcTCP, srcIsTCP := unwrapTCP(src)

	// Fast-path 1: kernel splice(2) on Linux when both ends are raw *net.TCPConn and no token-bucket throttle is active.
	if enableZeroCopy && srcIsTCP && userLim == nil && nodeLim.IsUnlimited() {
		if dstTCP, ok1 := unwrapTCP(dst); ok1 {
			for {
				if user != nil && user.IsDisabled() {
					return
				}
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

	slabSize := bufpool.MediumSize
	if isUpload {
		slabSize = bufpool.UploadSize
	}

	// Fast-path 2: when `src` is a raw *net.TCPConn (e.g. `remoteConn` download across all VMess/VLESS/Trojan/SS streams!),
	// use `syscall.RawConn.Read` on Unix so `bp` is returned to `bufpool` BEFORE parking in epoll on `EAGAIN`.
	// Active streams perform the exact same 1 `read(2)` syscall/chunk, while 4,000+ idle connections hold 0 B of heap!
	if srcIsTCP && tryCopyFromRawTCP(dst, srcTCP, slabSize, user, nodeLim, isUpload, idleTimeout) {
		return
	}

	bp := bufpool.Get(slabSize)
	buf := *bp
	defer bufpool.Put(bp)

	for {
		if user != nil && user.IsDisabled() {
			return
		}
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

type netConnWrapper interface {
	NetConn() net.Conn
}

type tcpUnwrapper interface {
	UnwrapTCP() (*net.TCPConn, bool)
}

func TuneTCP(c net.Conn) {
	cur := c
	for depth := 0; depth < 4 && cur != nil; depth++ {
		if tc, ok := cur.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(45 * time.Second)
			return
		}
		if w, ok := cur.(netConnWrapper); ok {
			cur = w.NetConn()
			continue
		}
		break
	}
}

func unwrapTCP(c net.Conn) (*net.TCPConn, bool) {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc, true
	}
	if u, ok := c.(tcpUnwrapper); ok {
		return u.UnwrapTCP()
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

func (p *PrependConn) NetConn() net.Conn {
	return p.Conn
}

func (p *PrependConn) CloseWrite() error {
	if cw, ok := p.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return p.Conn.SetReadDeadline(time.Now())
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
