package protocol

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/relay"
	"github.com/xmg665/xoga/internal/stats"
)

// handleVLESS processes VLESS v0 TCP (0x01) and UDP (0x02) connections.
// Wire format: Ver(1)==0 | UUID(16) | AddonLen(1) | Addon(N) | Cmd(1) | Port(2) | AddrType(1) | Addr
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
	if !ok {
		return
	}

	addonLen := int(fixed[17])
	if addonLen > 0 {
		var discard [256]byte
		if _, err := io.ReadFull(br, discard[:addonLen]); err != nil {
			return
		}
	}

	var cmdPort [3]byte
	if _, err := io.ReadFull(br, cmdPort[:]); err != nil {
		return
	}
	cmd := cmdPort[0]
	destPort := binary.BigEndian.Uint16(cmdPort[1:3])

	destHost, err := parseVLESSAddr(br)
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	respConn := &vlessRespConn{Conn: conn}

	switch cmd {
	case 0x01: // TCP
		var preread []byte
		if n := br.Buffered(); n > 0 {
			preread = make([]byte, n)
			_, _ = io.ReadFull(br, preread)
		}
		s.connectAndRelay(respConn, user, destHost, destPort, preread)
	case 0x02: // VLESS UDP (2-byte big-endian length-framed packets)
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

func (v *vlessRespConn) Write(p []byte) (int, error) {
	v.mu.Lock()
	if !v.sentResp {
		v.sentResp = true
		v.mu.Unlock()
		hdr := [2]byte{0x00, 0x00}
		bufs := net.Buffers{hdr[:], p}
		n, err := bufs.WriteTo(v.Conn)
		if n >= 2 {
			return int(n - 2), err
		}
		return 0, err
	}
	v.mu.Unlock()
	return v.Conn.Write(p)
}

func (s *Server) handleVLESSUDP(conn net.Conn, reader io.Reader, user *stats.UserEntry, destHost string, destPort uint16) {
	clientIP := relay.ExtractClientIP(conn.RemoteAddr())
	if err := user.AcquireConn(clientIP, s.tracker.IPTTLSeconds(), s.tracker.RedisLimiter()); err != nil {
		return
	}
	defer user.ReleaseConn()

	route := s.aclEng.Load().Decide(destHost, "", "")
	if route.Action == acl.ActionBlock {
		return
	}

	targetUDP, err := net.Dial("udp", net.JoinHostPort(destHost, strconv.Itoa(int(destPort))))
	if err != nil {
		return
	}
	defer targetUDP.Close()

	idleDur := time.Duration(s.cfg.UDPIdleSec) * time.Second
	if idleDur < 10*time.Second {
		idleDur = 60 * time.Second
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		bp := bufpool.Get(bufpool.MaxUDPSize)
		buf := *bp
		defer bufpool.Put(bp)

		for {
			_ = targetUDP.SetReadDeadline(time.Now().Add(idleDur))
			n, err := targetUDP.Read(buf[2:])
			if err != nil {
				return
			}
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
		if _, err := io.ReadFull(reader, lb[:]); err != nil {
			break
		}
		pktLen := int(binary.BigEndian.Uint16(lb[:]))
		if pktLen == 0 || pktLen > len(inBuf) {
			break
		}
		if _, err := io.ReadFull(reader, inBuf[:pktLen]); err != nil {
			break
		}
		if ul := user.EffectiveLimiter(); ul != nil {
			ul.Wait(pktLen)
		}
		s.tracker.NodeLimiter.Wait(pktLen)
		user.AddUpload(int64(pktLen))

		_, _ = targetUDP.Write(inBuf[:pktLen])
	}

	_ = targetUDP.Close()
	<-done
}
