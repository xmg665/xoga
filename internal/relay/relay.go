package relay

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xmg665/xoga/internal/acl"
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

// DialOutbound connects directly or via an outbound SOCKS5/HTTP proxy specified by ACL routing.
func DialOutbound(network, targetAddr string, route acl.OutboundTarget, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 45 * time.Second,
	}
	if route.Action == acl.ActionBlock {
		return nil, errors.New("blocked by ACL/audit rule")
	}
	if route.Action != acl.ActionProxy || route.Address == "" || network != "tcp" {
		return dialer.Dial(network, targetAddr)
	}

	u, err := url.Parse(route.Address)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		return dialSOCKS5(dialer, u, targetAddr, timeout)
	case "http":
		return dialHTTPConnect(dialer, u, targetAddr, timeout)
	default:
		return dialer.Dial(network, targetAddr)
	}
}

func dialSOCKS5(d *net.Dialer, proxyURL *url.URL, targetAddr string, timeout time.Duration) (net.Conn, error) {
	c, err := d.Dial("tcp", proxyURL.Host)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(timeout))

	var user, pass string
	if proxyURL.User != nil {
		user = proxyURL.User.Username()
		pass, _ = proxyURL.User.Password()
	}
	if user != "" {
		_, err = c.Write([]byte{0x05, 0x02, 0x00, 0x02})
	} else {
		_, err = c.Write([]byte{0x05, 0x01, 0x00})
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil || resp[0] != 0x05 {
		c.Close()
		return nil, errors.New("socks5 greeting failed")
	}
	if resp[1] == 0x02 {
		auth := make([]byte, 0, 3+len(user)+len(pass))
		auth = append(auth, 0x01, byte(len(user)))
		auth = append(auth, user...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, pass...)
		if _, err := c.Write(auth); err != nil {
			c.Close()
			return nil, err
		}
		if _, err := io.ReadFull(c, resp[:]); err != nil || resp[1] != 0x00 {
			c.Close()
			return nil, errors.New("socks5 auth rejected")
		}
	} else if resp[1] != 0x00 {
		c.Close()
		return nil, errors.New("socks5 unsupported auth")
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		c.Close()
		return nil, err
	}
	portNum, err := net.LookupPort("tcp", portStr)
	if err != nil {
		c.Close()
		return nil, err
	}

	req := make([]byte, 0, 7+len(host))
	req = append(req, 0x05, 0x01, 0x00)
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			req = append(req, 0x01)
			a4 := ip.As4()
			req = append(req, a4[:]...)
		} else {
			req = append(req, 0x04)
			a16 := ip.As16()
			req = append(req, a16[:]...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(portNum))
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}

	var rhead [4]byte
	if _, err := io.ReadFull(c, rhead[:]); err != nil || rhead[1] != 0x00 {
		c.Close()
		return nil, errors.New("socks5 connect failed")
	}
	var skip int
	switch rhead[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			c.Close()
			return nil, err
		}
		skip = int(l[0]) + 2
	}
	if skip > 0 {
		var discard [260]byte
		if _, err := io.ReadFull(c, discard[:skip]); err != nil {
			c.Close()
			return nil, err
		}
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func dialHTTPConnect(d *net.Dialer, proxyURL *url.URL, targetAddr string, timeout time.Duration) (net.Conn, error) {
	c, err := d.Dial("tcp", proxyURL.Host)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	req := "CONNECT " + targetAddr + " HTTP/1.1\r\nHost: " + targetAddr + "\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, " 200") {
		c.Close()
		return nil, errors.New("http connect proxy failed")
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			c.Close()
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	_ = c.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &PrependConn{Conn: c, Reader: br}, nil
	}
	return c, nil
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
