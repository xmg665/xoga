package protocol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/relay"
	"github.com/xmg665/xoga/internal/stats"
)

// handleVLESS processes VLESS v0 TCP (0x01), UDP (0x02), and Mux/XUDP (0x03) connections.
// Wire format: Ver(1)==0 | UUID(16) | AddonLen(1) | Addon(N) | Cmd(1) | [Port(2) | AddrType(1) | Addr when Cmd != 0x03]
func (s *Server) handleVLESS(conn net.Conn) {
	br := bufio.NewReaderSize(conn, 2048)

	var fixed [18]byte
	if _, err := io.ReadFull(br, fixed[:]); err != nil {
		return
	}
	if fixed[0] != 0x00 {
		return
	}

	var uuid [16]byte
	copy(uuid[:], fixed[1:17])

	idx := s.userIdx.Load()
	if idx == nil {
		return
	}
	user, ok := idx.ByUUID[uuid]
	if !ok || user.IsDisabled() {
		return
	}

	var flow string
	addonLen := int(fixed[17])
	if addonLen > 0 {
		var addonBuf [256]byte
		if _, err := io.ReadFull(br, addonBuf[:addonLen]); err != nil {
			return
		}
		flow = decodeVLESSAddonFlow(addonBuf[:addonLen])
	}
	if flow != "" && flow != FlowVision && flow != FlowVisionUDP443 {
		return
	}
	// Enforce configured Vision flow on TCP/Mux streams so unpadded downgrade probes are rejected
	nodeWantsVision := s.spec.Flow == FlowVision || s.spec.Flow == FlowVisionUDP443

	var cmdByte [1]byte
	if _, err := io.ReadFull(br, cmdByte[:]); err != nil {
		return
	}
	cmd := cmdByte[0]

	// Cmd 0x03 (RequestCommandMux / XUDP) omits Port & Address from the VLESS header!
	if cmd == 0x03 {
		if nodeWantsVision && flow == "" {
			return
		}
		_ = conn.SetDeadline(time.Time{})
		var muxStream net.Conn
		if flow == FlowVision || flow == FlowVisionUDP443 {
			muxStream = newVisionConn(conn, br, uuid)
		} else {
			var r io.Reader = conn
			if br.Buffered() > 0 {
				r = br
			}
			muxStream = &vlessRespConn{Conn: &relay.PrependConn{Conn: conn, Reader: r}}
		}
		s.handleVLESSMux(muxStream, user, flow)
		return
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(br, portBytes[:]); err != nil {
		return
	}
	destPort := binary.BigEndian.Uint16(portBytes[:])

	destHost, err := parseVLESSAddr(br)
	if err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	switch cmd {
	case 0x01: // TCP (or Mux.Cool when destHost == "v1.mux.cool")
		if nodeWantsVision && flow == "" {
			return
		}
		if strings.EqualFold(destHost, "v1.mux.cool") {
			var muxStream net.Conn
			if flow == FlowVision || flow == FlowVisionUDP443 {
				muxStream = newVisionConn(conn, br, uuid)
			} else {
				var r io.Reader = conn
				if br.Buffered() > 0 {
					r = br
				}
				muxStream = &vlessRespConn{Conn: &relay.PrependConn{Conn: conn, Reader: r}}
			}
			s.handleVLESSMux(muxStream, user, flow)
			return
		}
		if flow == FlowVision || flow == FlowVisionUDP443 {
			visConn := newVisionConn(conn, br, uuid)
			s.connectAndRelay(visConn, user, destHost, destPort, nil)
			return
		}
		respConn := &vlessRespConn{Conn: conn}
		var preread []byte
		if n := br.Buffered(); n > 0 {
			preread = make([]byte, n)
			_, _ = io.ReadFull(br, preread)
		}
		s.connectAndRelay(respConn, user, destHost, destPort, preread)
	case 0x02: // VLESS UDP (2-byte big-endian length-framed packets)
		if (flow == FlowVision || s.spec.Flow == FlowVision) && destPort == 443 {
			// Per XTLS-Vision spec, reject UDP:443 QUIC so client falls back to TCP TLS 1.3
			return
		}
		respConn := &vlessRespConn{Conn: conn}
		var r io.Reader = br
		s.handleVLESSUDP(respConn, r, user, destHost, destPort)
	}
}

// parseVLESSAddr parses VLESS/VMess address format: 0x01=IPv4, 0x02=Domain, 0x03=IPv6.
func parseVLESSAddr(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}
	switch atyp[0] {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	case 0x02: // Domain
		var dlen [1]byte
		if _, err := io.ReadFull(r, dlen[:]); err != nil {
			return "", err
		}
		buf := make([]byte, int(dlen[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return strings.TrimSpace(string(buf)), nil
	case 0x03: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	default:
		return "", fmt.Errorf("invalid VLESS address type 0x%02x", atyp[0])
	}
}

// vlessRespConn lazily prepends the 2-byte VLESS response header `[0x00, 0x00]` on the first server write
// using scatter-gather I/O (`net.Buffers`), saving an extra TCP packet and syscall.
type vlessRespConn struct {
	net.Conn
	mu       sync.Mutex
	sentResp bool
}

func (v *vlessRespConn) NetConn() net.Conn {
	return v.Conn
}

func (v *vlessRespConn) CanHalfCloseWrite() bool {
	if hc, ok := v.Conn.(interface{ CanHalfCloseWrite() bool }); ok {
		return hc.CanHalfCloseWrite()
	}
	_, ok := v.Conn.(interface{ CloseWrite() error })
	return ok
}

func (v *vlessRespConn) CloseWrite() error {
	if cw, ok := v.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("half-close unsupported")
}

func (v *vlessRespConn) FlushResponseHeader() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.sentResp {
		v.sentResp = true
		_, err := v.Conn.Write([]byte{0x00, 0x00})
		return err
	}
	return nil
}

func (v *vlessRespConn) Write(p []byte) (int, error) {
	v.mu.Lock()
	if !v.sentResp {
		v.sentResp = true
		if _, isTCP := v.Conn.(*net.TCPConn); isTCP {
			hdr := [2]byte{0x00, 0x00}
			bufs := net.Buffers{hdr[:], p}
			n, err := bufs.WriteTo(v.Conn)
			v.mu.Unlock()
			if n >= 2 {
				return int(n - 2), err
			}
			return 0, err
		}
		// Coalesce 2-byte VLESS header + first payload into one Write for TLS / WS / REALITY
		// so they emit 1 single encrypted TLS record / WS frame instead of a fingerprintable 2-byte frame!
		bp := bufpool.Get(2 + len(p))
		combined := (*bp)[:2+len(p)]
		combined[0] = 0x00
		combined[1] = 0x00
		copy(combined[2:], p)
		n, err := v.Conn.Write(combined)
		bufpool.Put(bp)
		v.mu.Unlock()
		if n >= 2 {
			return n - 2, err
		}
		return 0, err
	}
	v.mu.Unlock()
	return v.Conn.Write(p)
}

func (s *Server) handleVLESSUDP(conn net.Conn, reader io.Reader, user *stats.UserEntry, destHost string, destPort uint16) {
	clientIP := relay.ExtractClientIP(conn.RemoteAddr())
	connID, err := user.AcquireSession(clientIP, s.tracker.IPTTLSeconds(), s.tracker.RedisLimiter(), conn)
	if err != nil {
		return
	}
	defer user.ReleaseSession(connID)

	route := s.aclEng.Load().DecideForNode(s.cfg.NodeID, destHost, destPort, "", "")
	if route.Action == acl.ActionBlock {
		return
	}

	rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	udpAddr, err := relay.ResolveUDPTargetForRoute(rctx, destHost, destPort, route, s.dnsRes)
	if err != nil {
		rcancel()
		return
	}
	targetUDP, err := relay.DialUDPForRoute(rctx, route, udpAddr.IP.To4() == nil, s.dnsRes)
	rcancel()
	if err != nil {
		return
	}
	defer targetUDP.Close()

	idleDur := s.udpIdleDur(10*time.Second, 60*time.Second)

	var lastActive atomic.Int64
	lastActive.Store(time.Now().UnixNano())

	done := make(chan struct{})
	go func() {
		defer func() {
			_ = conn.Close()
			close(done)
		}()
		bp := bufpool.Get(bufpool.MaxUDPSize)
		buf := *bp
		defer bufpool.Put(bp)

		for {
			_ = targetUDP.SetReadDeadline(time.Now().Add(idleDur))
			n, _, err := targetUDP.ReadFrom(buf[2:])
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() && time.Since(time.Unix(0, lastActive.Load())) < idleDur {
					continue
				}
				return
			}
			lastActive.Store(time.Now().UnixNano())
			if ul := user.EffectiveLimiter(); ul != nil {
				ul.Wait(n)
			}
			s.tracker.NodeLimiter.Wait(n)
			user.AddDownload(int64(n))

			binary.BigEndian.PutUint16(buf[0:2], uint16(n))
			_ = conn.SetWriteDeadline(time.Now().Add(idleDur))
			if _, werr := conn.Write(buf[:2+n]); werr != nil {
				return
			}
		}
	}()

	bp := bufpool.Get(bufpool.MaxUDPSize)
	inBuf := *bp
	defer bufpool.Put(bp)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(idleDur))
		var lb [2]byte
		// Read the first byte separately: if 0 bytes were read before timeout while
		// downlink is still active, we can safely retry without desyncing framing.
		rn, err := reader.Read(lb[:1])
		if rn == 0 {
			var ne net.Error
			if err != nil && errors.As(err, &ne) && ne.Timeout() && time.Since(time.Unix(0, lastActive.Load())) < idleDur {
				continue
			}
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(idleDur))
		if _, err := io.ReadFull(reader, lb[1:]); err != nil {
			break
		}
		pktLen := int(binary.BigEndian.Uint16(lb[:]))
		if pktLen == 0 || pktLen > len(inBuf) {
			break
		}
		if _, err := io.ReadFull(reader, inBuf[:pktLen]); err != nil {
			break
		}
		lastActive.Store(time.Now().UnixNano())
		if ul := user.EffectiveLimiter(); ul != nil {
			ul.Wait(pktLen)
		}
		s.tracker.NodeLimiter.Wait(pktLen)
		user.AddUpload(int64(pktLen))

		_, _ = targetUDP.WriteTo(inBuf[:pktLen], udpAddr)
	}

	_ = targetUDP.Close()
	<-done
}

type xudpSubSession struct {
	pc       net.PacketConn
	lastSeen atomic.Int64
}

type xudpKey struct {
	sid      uint16
	routeKey string
}

type xudpDest struct {
	host string
	port uint16
}

// handleVLESSMux implements Xray VLESS `cmd == 0x03` (`RequestCommandMux` / XUDP) UDP sub-session framing,
// which is the default UDP transport in Xray-core / v2rayN / Mihomo and required for UDP over `xtls-rprx-vision`.
func (s *Server) handleVLESSMux(conn net.Conn, user *stats.UserEntry, flow string) {
	clientIP := relay.ExtractClientIP(conn.RemoteAddr())
	connID, err := user.AcquireMuxSession(clientIP, s.tracker.IPTTLSeconds(), s.tracker.RedisLimiter(), conn)
	if err != nil {
		return
	}
	defer user.ReleaseMuxSession(connID)

	idleDur := s.udpIdleDur(10*time.Second, 60*time.Second)
	muxIdleDur := idleDur
	if connIdle := s.connIdleDur(15*time.Second, 60*time.Second); connIdle > muxIdleDur {
		muxIdleDur = connIdle
	}

	var lastActive atomic.Int64
	lastActive.Store(time.Now().UnixNano())
	touchMux := func() {
		lastActive.Store(time.Now().UnixNano())
	}

	var writeMu sync.Mutex
	writeXUDP := func(frame []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(muxIdleDur))
		_, werr := conn.Write(frame)
		if werr == nil {
			touchMux()
		}
		return werr
	}

	var sessMu sync.Mutex
	sessions := make(map[xudpKey]*xudpSubSession)
	lastDests := make(map[uint16]xudpDest)
	tcpSessions := make(map[uint16]*muxTCPSubSession)
	defer func() {
		sessMu.Lock()
		for _, us := range sessions {
			_ = us.pc.Close()
		}
		for _, ts := range tcpSessions {
			ts.abort()
		}
		sessions = nil
		lastDests = nil
		tcpSessions = nil
		sessMu.Unlock()
	}()

	bp := bufpool.Get(bufpool.MaxUDPSize)
	inBuf := *bp
	defer bufpool.Put(bp)

	var metaLenBuf [2]byte
	var metaBuf [512]byte

	for {
		if user.IsDisabled() {
			return
		}
		if err := readFullActive(conn, conn, metaLenBuf[:], muxIdleDur, &lastActive, user.IsDisabled); err != nil {
			return
		}
		metaLen := int(binary.BigEndian.Uint16(metaLenBuf[:]))
		if metaLen < 4 || metaLen > len(metaBuf) {
			return
		}
		if err := readFullActive(conn, conn, metaBuf[:metaLen], muxIdleDur, &lastActive, user.IsDisabled); err != nil {
			return
		}
		sid := binary.BigEndian.Uint16(metaBuf[0:2])
		status := metaBuf[2]
		opt := metaBuf[3]

		var host string
		var port uint16
		var netType byte
		hasAddr := false

		if (status == 0x01 || status == 0x02) && metaLen > 4 {
			mr := bytes.NewReader(metaBuf[4:metaLen])
			var nb [3]byte
			if _, err := io.ReadFull(mr, nb[:]); err == nil {
				netType = nb[0]
				port = binary.BigEndian.Uint16(nb[1:3])
				if h, aerr := parseVLESSAddr(mr); aerr == nil {
					host = h
					hasAddr = true
				}
			}
		}

		var payload []byte
		if (opt & 0x01) != 0 {
			var dlenBuf [2]byte
			if err := readFullActive(conn, conn, dlenBuf[:], muxIdleDur, &lastActive, user.IsDisabled); err != nil {
				return
			}
			dlen := int(binary.BigEndian.Uint16(dlenBuf[:]))
			if dlen > len(inBuf) {
				return
			}
			if dlen > 0 {
				if err := readFullActive(conn, conn, inBuf[:dlen], muxIdleDur, &lastActive, user.IsDisabled); err != nil {
					return
				}
				payload = inBuf[:dlen]
			}
		}

		if status == 0x04 { // KeepAlive
			continue
		}
		if status == 0x03 { // End
			sessMu.Lock()
			tSub := tcpSessions[sid]
			if tSub != nil && (opt&0x02) != 0 {
				delete(tcpSessions, sid)
			}
			delete(lastDests, sid)
			var toClose []*xudpSubSession
			for k, us := range sessions {
				if k.sid == sid {
					delete(sessions, k)
					toClose = append(toClose, us)
				}
			}
			sessMu.Unlock()
			if tSub != nil {
				if len(payload) > 0 {
					tSub.enqueue(payload)
				}
				if (opt & 0x02) != 0 {
					tSub.abort()
				} else {
					tSub.closeClientTx()
				}
			}
			for _, us := range toClose {
				_ = us.pc.Close()
			}
			continue
		}
		if status == 0x01 && hasAddr && netType == 0x01 { // Mux.Cool TCP sub-session
			sessMu.Lock()
			if prev := tcpSessions[sid]; prev != nil {
				delete(tcpSessions, sid)
				prev.abort()
			}
			tooMany := len(tcpSessions) >= 256
			var tSub *muxTCPSubSession
			if !tooMany {
				if user.AcquireSubStream() != nil {
					tooMany = true
				} else {
					tSub = newMuxTCPSubSession()
					tcpSessions[sid] = tSub
				}
			}
			sessMu.Unlock()
			if tooMany {
				_ = writeXUDP(encodeMuxTCPEndFrame(sid, true))
				continue
			}
			if len(payload) > 0 {
				tSub.enqueue(payload)
			}
			subID := sid
			go s.runMuxTCPSubSession(subID, host, port, user, tSub, writeXUDP, touchMux, func() {
				sessMu.Lock()
				if tcpSessions != nil && tcpSessions[subID] == tSub {
					delete(tcpSessions, subID)
				}
				sessMu.Unlock()
			})
			continue
		}
		if status == 0x02 {
			sessMu.Lock()
			tSub := tcpSessions[sid]
			sessMu.Unlock()
			if tSub != nil {
				if len(payload) > 0 {
					tSub.enqueue(payload)
				}
				continue
			}
		}
		if hasAddr && netType != 0x02 {
			continue
		}
		if (flow == FlowVision || s.spec.Flow == FlowVision) && hasAddr && port == 443 {
			continue
		}

		sessMu.Lock()
		if !hasAddr {
			if ld, ok := lastDests[sid]; ok && ld.host != "" {
				host = ld.host
				port = ld.port
				hasAddr = true
			}
		} else {
			if len(lastDests) >= 512 {
				if _, exists := lastDests[sid]; !exists {
					for k := range lastDests {
						delete(lastDests, k)
						break
					}
				}
			}
			lastDests[sid] = xudpDest{host: host, port: port}
		}
		sessMu.Unlock()
		if !hasAddr || len(payload) == 0 {
			continue
		}

		route := s.aclEng.Load().DecideForNode(s.cfg.NodeID, host, port, "", "")
		if route.Action == acl.ActionBlock {
			continue
		}
		rctx, rcancel := context.WithTimeout(context.Background(), 4*time.Second)
		dstUDP, err := relay.ResolveUDPTargetForRoute(rctx, host, port, route, s.dnsRes)
		if err != nil {
			rcancel()
			continue
		}
		isIPv6 := dstUDP.IP.To4() == nil
		key := xudpKey{sid: sid, routeKey: udpRouteKey(route, isIPv6)}

		sessMu.Lock()
		if sessions == nil {
			sessMu.Unlock()
			rcancel()
			return
		}
		us := sessions[key]
		if us != nil {
			us.lastSeen.Store(time.Now().UnixNano())
			sessMu.Unlock()
			rcancel()
		} else {
			if len(sessions) >= 256 {
				sessMu.Unlock()
				rcancel()
				continue
			}
			sessMu.Unlock()

			// Dial outbound UDP socket outside sessMu so slow SOCKS5 dials never stall other sub-sessions.
			pc, derr := relay.DialUDPForRoute(rctx, route, isIPv6, s.dnsRes)
			rcancel()
			if derr != nil {
				continue
			}

			sessMu.Lock()
			if sessions == nil {
				sessMu.Unlock()
				_ = pc.Close()
				return
			}
			if existing := sessions[key]; existing != nil {
				existing.lastSeen.Store(time.Now().UnixNano())
				us = existing
				sessMu.Unlock()
				_ = pc.Close()
			} else {
				us = &xudpSubSession{pc: pc}
				us.lastSeen.Store(time.Now().UnixNano())
				sessions[key] = us
				sessMu.Unlock()

				go func(k xudpKey, sub *xudpSubSession) {
					defer func() {
						_ = sub.pc.Close()
						sessMu.Lock()
						if sessions != nil && sessions[k] == sub {
							delete(sessions, k)
						}
						sessMu.Unlock()
					}()
					rbp := bufpool.Get(bufpool.MaxUDPSize)
					rbuf := *rbp
					defer bufpool.Put(rbp)

					for {
						if user.IsDisabled() {
							return
						}
						_ = sub.pc.SetReadDeadline(time.Now().Add(idleDur))
						rn, raddr, rerr := sub.pc.ReadFrom(rbuf)
						if rerr != nil {
							var ne net.Error
							if errors.As(rerr, &ne) && ne.Timeout() && time.Since(time.Unix(0, sub.lastSeen.Load())) < idleDur {
								continue
							}
							return
						}
						ua, ok := raddr.(*net.UDPAddr)
						if !ok || ua == nil || ua.IP == nil || rn <= 0 {
							continue
						}
						sub.lastSeen.Store(time.Now().UnixNano())
						touchMux()
						if ul := user.EffectiveLimiter(); ul != nil {
							ul.Wait(rn)
						}
						s.tracker.NodeLimiter.Wait(rn)
						user.AddDownload(int64(rn))

						frame := encodeXUDPReplyFrame(k.sid, ua, rbuf[:rn])
						if frame == nil {
							continue
						}
						if writeXUDP(frame) != nil {
							return
						}
					}
				}(key, us)
			}
		}

		if ul := user.EffectiveLimiter(); ul != nil {
			ul.Wait(len(payload))
		}
		s.tracker.NodeLimiter.Wait(len(payload))
		user.AddUpload(int64(len(payload)))
		_, _ = us.pc.WriteTo(payload, dstUDP)
	}
}

func encodeXUDPReplyFrame(sid uint16, ua *net.UDPAddr, data []byte) []byte {
	if ua == nil || ua.IP == nil {
		return nil
	}
	ip4 := ua.IP.To4()
	ip16 := ua.IP.To16()
	if ip4 == nil && ip16 == nil {
		return nil
	}
	metaLen := 4 + 1 + 2 + 1 + 16
	if ip4 != nil {
		metaLen = 4 + 1 + 2 + 1 + 4
	}
	out := make([]byte, 2+metaLen+2+len(data))
	binary.BigEndian.PutUint16(out[0:2], uint16(metaLen))
	binary.BigEndian.PutUint16(out[2:4], sid)
	out[4] = 0x02 // SessionStatusKeep
	out[5] = 0x01 // OptionData
	out[6] = 0x02 // Network UDP
	binary.BigEndian.PutUint16(out[7:9], uint16(ua.Port))
	pos := 9
	if ip4 != nil {
		out[pos] = 0x01
		pos++
		pos += copy(out[pos:], ip4)
	} else {
		out[pos] = 0x03
		pos++
		pos += copy(out[pos:], ip16)
	}
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(len(data)))
	copy(out[pos+2:], data)
	return out
}
