package protocol

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/logger"
	"github.com/xmg665/xoga/internal/relay"
	"github.com/xmg665/xoga/internal/stats"
)

// handleTrojan processes Trojan TCP (0x01) and Trojan-UDP Associate (0x03) streams.
// Wire format: HexSHA224(56) + CRLF(2) + Cmd(1) + SOCKS5Addr + CRLF(2) + Payload
func (s *Server) handleTrojan(conn net.Conn) {
	br := bufio.NewReaderSize(conn, 2048)

	var hashHdr [58]byte
	if _, err := io.ReadFull(br, hashHdr[:]); err != nil {
		return
	}
	if hashHdr[56] != '\r' || hashHdr[57] != '\n' {
		return
	}

	var key [56]byte
	copy(key[:], hashHdr[:56])

	idx := s.userIdx.Load()
	if idx == nil {
		return
	}
	user, ok := idx.ByTrojan[key]
	if !ok || user.IsDisabled() {
		return
	}

	var cmd [1]byte
	if _, err := io.ReadFull(br, cmd[:]); err != nil {
		return
	}
	destHost, destPort, err := parseSOCKS5Addr(br)
	if err != nil {
		return
	}
	var crlf [2]byte
	if _, err := io.ReadFull(br, crlf[:]); err != nil || crlf[0] != '\r' || crlf[1] != '\n' {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	switch cmd[0] {
	case 0x01: // TCP Connect
		var preread []byte
		if n := br.Buffered(); n > 0 {
			preread = make([]byte, n)
			_, _ = io.ReadFull(br, preread)
		}
		s.connectAndRelay(conn, user, destHost, destPort, preread)
	case 0x03: // Trojan UDP Associate over stream
		wrapped := net.Conn(conn)
		if br.Buffered() > 0 {
			wrapped = &relay.PrependConn{Conn: conn, Reader: br}
		}
		s.handleTrojanUDP(wrapped, user)
	}
}

func (s *Server) handleTrojanUDP(conn net.Conn, user *stats.UserEntry) {
	clientIP := relay.ExtractClientIP(conn.RemoteAddr())
	connID, err := user.AcquireSession(clientIP, s.tracker.IPTTLSeconds(), s.tracker.RedisLimiter(), conn)
	if err != nil {
		return
	}
	defer user.ReleaseSession(connID)

	idleDur := time.Duration(s.cfg.UDPIdleSec) * time.Second
	if idleDur < 10*time.Second {
		idleDur = 60 * time.Second
	}

	var lastActive atomic.Int64
	lastActive.Store(time.Now().Unix())

	var writeMu sync.Mutex
	var sockMu sync.Mutex
	sockets := make(map[string]net.PacketConn)
	streamClosed := false
	var wg sync.WaitGroup

	closeAllSockets := func() {
		sockMu.Lock()
		streamClosed = true
		for _, pc := range sockets {
			_ = pc.Close()
		}
		sockets = nil
		sockMu.Unlock()
	}

	startReader := func(key string, pc net.PacketConn) {
		wg.Add(1)
		go func() {
			defer func() {
				_ = pc.Close()
				sockMu.Lock()
				remaining := 0
				if sockets != nil && sockets[key] == pc {
					delete(sockets, key)
					remaining = len(sockets)
				}
				wasClosed := streamClosed
				sockMu.Unlock()
				if !wasClosed && remaining == 0 {
					_ = conn.Close()
				}
				wg.Done()
			}()
			bp := bufpool.Get(bufpool.MaxUDPSize)
			buf := *bp
			defer bufpool.Put(bp)

			for {
				if user.IsDisabled() {
					_ = conn.Close()
					return
				}
				_ = pc.SetReadDeadline(time.Now().Add(idleDur))
				n, raddr, rerr := pc.ReadFrom(buf)
				if rerr != nil {
					var ne net.Error
					if errors.As(rerr, &ne) && ne.Timeout() && time.Since(time.Unix(lastActive.Load(), 0)) < idleDur {
						continue
					}
					return
				}
				ua, ok := raddr.(*net.UDPAddr)
				if !ok {
					continue
				}
				lastActive.Store(time.Now().Unix())
				if ul := user.EffectiveLimiter(); ul != nil {
					ul.Wait(n)
				}
				s.tracker.NodeLimiter.Wait(n)
				user.AddDownload(int64(n))

				pkt := encodeTrojanUDPPacket(ua, buf[:n])
				if pkt == nil {
					continue
				}
				writeMu.Lock()
				_ = conn.SetWriteDeadline(time.Now().Add(idleDur))
				_, werr := conn.Write(pkt)
				writeMu.Unlock()
				if werr != nil {
					_ = conn.Close()
					return
				}
			}
		}()
	}

	getOrDialSocket := func(ctx context.Context, route acl.OutboundTarget, isIPv6 bool) (net.PacketConn, error) {
		key := udpRouteKey(route, isIPv6)
		sockMu.Lock()
		if streamClosed || sockets == nil {
			sockMu.Unlock()
			return nil, net.ErrClosed
		}
		if pc, ok := sockets[key]; ok {
			sockMu.Unlock()
			return pc, nil
		}
		if len(sockets) >= 8 {
			sockMu.Unlock()
			return nil, errors.New("too many UDP route sockets in Trojan UDP session")
		}
		sockMu.Unlock()

		newPC, derr := relay.DialUDPForRoute(ctx, route, isIPv6, s.dnsRes)
		if derr != nil {
			return nil, derr
		}

		sockMu.Lock()
		if streamClosed || sockets == nil {
			sockMu.Unlock()
			_ = newPC.Close()
			return nil, net.ErrClosed
		}
		if existing, ok := sockets[key]; ok {
			sockMu.Unlock()
			_ = newPC.Close()
			return existing, nil
		}
		sockets[key] = newPC
		startReader(key, newPC)
		sockMu.Unlock()
		return newPC, nil
	}

	// Trojan stream -> Remote UDP
	bp := bufpool.Get(bufpool.MaxUDPSize)
	payload := *bp
	defer bufpool.Put(bp)

	for {
		if user.IsDisabled() {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(idleDur))
		// Read the first byte (ATYP) separately: only retry on timeout when 0 bytes
		// were consumed so partial reads can never desynchronize the stream.
		var atyp [1]byte
		rn, err := conn.Read(atyp[:])
		if rn == 0 {
			var ne net.Error
			if err != nil && errors.As(err, &ne) && ne.Timeout() && time.Since(time.Unix(lastActive.Load(), 0)) < idleDur {
				continue
			}
			break
		}
		host, port, err := parseSOCKS5AddrWithAtyp(conn, atyp[0])
		if err != nil {
			break
		}
		var lenCRLF [4]byte
		if _, err := io.ReadFull(conn, lenCRLF[:]); err != nil {
			break
		}
		pktLen := int(binary.BigEndian.Uint16(lenCRLF[0:2]))
		if lenCRLF[2] != '\r' || lenCRLF[3] != '\n' || pktLen > len(payload) {
			break
		}
		if _, err := io.ReadFull(conn, payload[:pktLen]); err != nil {
			break
		}
		lastActive.Store(time.Now().Unix())

		route := s.aclEng.Load().DecideForNode(s.cfg.NodeID, host, port, "", "")
		if route.Action == acl.ActionBlock {
			continue
		}
		rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
		dstAddr, err := relay.ResolveUDPTargetForRoute(rctx, host, port, route, s.dnsRes)
		if err != nil {
			rcancel()
			logger.Debugf("trojan udp resolve %s failed: %v", host, err)
			continue
		}
		udpConn, derr := getOrDialSocket(rctx, route, dstAddr.IP.To4() == nil)
		rcancel()
		if derr != nil {
			logger.Debugf("trojan udp dial %s failed: %v", host, derr)
			continue
		}

		if ul := user.EffectiveLimiter(); ul != nil {
			ul.Wait(pktLen)
		}
		s.tracker.NodeLimiter.Wait(pktLen)
		user.AddUpload(int64(pktLen))

		_, _ = udpConn.WriteTo(payload[:pktLen], dstAddr)
	}

	closeAllSockets()
	wg.Wait()
}

func encodeTrojanUDPPacket(ua *net.UDPAddr, data []byte) []byte {
	if ua == nil || ua.IP == nil {
		return nil
	}
	ip4 := ua.IP.To4()
	ip16 := ua.IP.To16()
	if ip4 == nil && ip16 == nil {
		return nil
	}
	addrLen := 1 + 16 + 2
	if ip4 != nil {
		addrLen = 1 + 4 + 2
	}
	out := make([]byte, 0, addrLen+4+len(data))
	if ip4 != nil {
		out = append(out, 0x01)
		out = append(out, ip4...)
	} else {
		out = append(out, 0x04)
		out = append(out, ip16...)
	}
	var p2 [2]byte
	binary.BigEndian.PutUint16(p2[:], uint16(ua.Port))
	out = append(out, p2[:]...)
	binary.BigEndian.PutUint16(p2[:], uint16(len(data)))
	out = append(out, p2[:]...)
	out = append(out, '\r', '\n')
	out = append(out, data...)
	return out
}

var _ = errors.New
