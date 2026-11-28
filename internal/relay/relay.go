package relay

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/limiter"
	"github.com/xmg665/xoga/internal/stats"
)

const spliceChunkSize = 256 * 1024 // 256 KiB kernel splice window for responsive dynamic throttling & live accounting

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
	var abortUpload atomic.Bool
	var abortDownload atomic.Bool
	var uploadPeerDone atomic.Bool
	var downloadPeerDone atomic.Bool
	var lastActive atomic.Int64
	lastActive.Store(time.Now().UnixNano())

	// Upload: client -> remote (1 child goroutine)
	go func() {
		defer close(uploadDone)
		copyOneWay(remoteConn, clientConn, user, nodeLim, true, idleTimeout, enableZeroCopy, &abortUpload, &uploadPeerDone, &lastActive)
		if user != nil && user.IsDisabled() {
			// User was disabled/kicked mid-stream -> immediately sever remoteConn too so download never lingers!
			abortDownload.Store(true)
			_ = remoteConn.Close()
			_ = clientConn.Close()
			return
		}
		if !tryHalfCloseWrite(remoteConn) {
			// Outbounds without TCP half-close (e.g. SS/WS) may still be actively sending the HTTP/RPC response!
			// Do NOT abort download at 0ms; bound idle response wait to 15s while letting active downloads finish.
			downloadPeerDone.Store(true)
			_ = remoteConn.SetReadDeadline(time.Now().Add(min(idleTimeout, 15*time.Second)))
		}
	}()

	// Download: remote -> client (inline on current goroutine -> eliminates 1 goroutine + 4-8 KiB stack per connection!)
	copyOneWay(clientConn, remoteConn, user, nodeLim, false, idleTimeout, enableZeroCopy, &abortDownload, &downloadPeerDone, &lastActive)
	if user != nil && user.IsDisabled() {
		abortUpload.Store(true)
		_ = clientConn.Close()
		_ = remoteConn.Close()
	} else {
		flushResponseHeader(clientConn)
		if !tryHalfCloseWrite(clientConn) {
			// Framing protocols without half-close (VMess, WS, SS, AnyTLS) cannot notify peer via CloseWrite:
			// atomically flag abortUpload BEFORE SetReadDeadline(now) so the upload loop can never clobber it back to +idleTimeout!
			abortUpload.Store(true)
			_ = clientConn.SetReadDeadline(time.Now())
		} else {
			// Bound half-closed client linger to at most 15s once remote has already closed.
			uploadPeerDone.Store(true)
			_ = clientConn.SetReadDeadline(time.Now().Add(min(idleTimeout, 15*time.Second)))
		}
	}

	<-uploadDone
}

func isNetTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func effectiveIdle(idleTimeout time.Duration, peerDone *atomic.Bool) time.Duration {
	if peerDone != nil && peerDone.Load() {
		return min(idleTimeout, 15*time.Second)
	}
	return idleTimeout
}

func isStreamStillActive(lastActive *atomic.Int64, effIdle time.Duration) bool {
	if lastActive == nil {
		return false
	}
	return time.Since(time.Unix(0, lastActive.Load())) < effIdle
}

func copyOneWay(
	dst net.Conn,
	src net.Conn,
	user *stats.UserEntry,
	nodeLim *limiter.Bucket,
	isUpload bool,
	idleTimeout time.Duration,
	enableZeroCopy bool,
	abortPeer *atomic.Bool,
	peerDone *atomic.Bool,
	lastActive *atomic.Int64,
) {
	srcTCP, srcIsTCP := unwrapTCP(src)

	// Fast-path 1: kernel splice(2) on Linux when both ends are raw *net.TCPConn and no token-bucket throttle is active.
	// Re-checks user & node limiters every 256 KiB so dynamic speed limits (`dy_limit`) take effect mid-stream,
	// and preserves active low-rate & unidirectional streams using shared bidirectional `lastActive`!
	if enableZeroCopy && srcIsTCP {
		if dstTCP, ok1 := unwrapTCP(dst); ok1 {
			for {
				if (user != nil && user.IsDisabled()) || (abortPeer != nil && abortPeer.Load()) {
					return
				}
				if (user != nil && user.EffectiveLimiter() != nil) || !nodeLim.IsUnlimited() {
					// Dynamic or panel rate limit became active -> seamlessly drop down to throttled path!
					break
				}
				effIdle := effectiveIdle(idleTimeout, peerDone)
				// Use half of effIdle as the splice read-deadline slice so low-rate
				// unidirectional splice transfers (<256 KiB per window) always return
				// and refresh shared `lastActive` well before the peer direction reaches effIdle.
				spliceSlice := effIdle / 2
				if spliceSlice < 10*time.Millisecond {
					spliceSlice = effIdle
				}
				now := time.Now()
				_ = srcTCP.SetReadDeadline(now.Add(spliceSlice))
				_ = dstTCP.SetWriteDeadline(now.Add(effIdle + 15*time.Second))
				if abortPeer != nil && abortPeer.Load() {
					_ = srcTCP.SetReadDeadline(now)
					return
				}
				n, err := dstTCP.ReadFrom(io.LimitReader(srcTCP, spliceChunkSize))
				if n > 0 {
					if lastActive != nil {
						lastActive.Store(time.Now().UnixNano())
					}
					if user != nil {
						if isUpload {
							user.AddUpload(n)
						} else {
							user.AddDownload(n)
						}
					}
				}
				if err == nil {
					if n == 0 {
						return
					}
					continue
				}
				if isNetTimeout(err) && time.Since(now) < effIdle+10*time.Second {
					effIdleNow := effectiveIdle(idleTimeout, peerDone)
					if n > 0 || isStreamStillActive(lastActive, effIdleNow) {
						continue
					}
				}
				return
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
	if srcIsTCP && tryCopyFromRawTCP(dst, srcTCP, slabSize, user, nodeLim, isUpload, idleTimeout, abortPeer, peerDone, lastActive) {
		return
	}

	bp := bufpool.Get(slabSize)
	buf := *bp
	defer bufpool.Put(bp)

	for {
		if (user != nil && user.IsDisabled()) || (abortPeer != nil && abortPeer.Load()) {
			return
		}
		effIdle := effectiveIdle(idleTimeout, peerDone)
		_ = src.SetReadDeadline(time.Now().Add(effIdle))
		if abortPeer != nil && abortPeer.Load() {
			_ = src.SetReadDeadline(time.Now())
			return
		}
		nr, rerr := src.Read(buf)
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
			nw, werr := writeFull(dst, buf[:nr])
			if werr != nil || nw != nr {
				return
			}
		}
		if rerr != nil {
			if isNetTimeout(rerr) && !(user != nil && user.IsDisabled()) && !(abortPeer != nil && abortPeer.Load()) {
				if isStreamStillActive(lastActive, effectiveIdle(idleTimeout, peerDone)) {
					continue
				}
			}
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

type halfCloseChecker interface {
	CanHalfCloseWrite() bool
}

type responseHeaderFlusher interface {
	FlushResponseHeader() error
}

func flushResponseHeader(c net.Conn) {
	if rf, ok := c.(responseHeaderFlusher); ok {
		_ = rf.FlushResponseHeader()
	}
}

func canConnHalfCloseWrite(c net.Conn) bool {
	if c == nil {
		return false
	}
	if hc, ok := c.(halfCloseChecker); ok {
		return hc.CanHalfCloseWrite()
	}
	_, ok := c.(closeWriter)
	return ok
}

func tryHalfCloseWrite(c net.Conn) bool {
	if !canConnHalfCloseWrite(c) {
		return false
	}
	if cw, ok := c.(closeWriter); ok {
		return cw.CloseWrite() == nil
	}
	return false
}

// PrependConn wraps a net.Conn when bytes have already been buffered/peeked during handshake or sniffing.
type PrependConn struct {
	net.Conn
	Reader io.Reader
}

func (p *PrependConn) NetConn() net.Conn {
	return p.Conn
}

func (p *PrependConn) RawWriteConn() net.Conn {
	return p.Conn
}

func (p *PrependConn) CanHalfCloseWrite() bool {
	return canConnHalfCloseWrite(p.Conn)
}

func (p *PrependConn) CloseWrite() error {
	if cw, ok := p.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return errors.New("half-close unsupported")
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
