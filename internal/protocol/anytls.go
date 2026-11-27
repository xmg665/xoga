package protocol

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/relay"
	"github.com/xmg665/xoga/internal/sniff"
	"github.com/xmg665/xoga/internal/stats"
)

const (
	anytlsCmdWaste               byte = 0
	anytlsCmdSYN                 byte = 1
	anytlsCmdPSH                 byte = 2
	anytlsCmdFIN                 byte = 3
	anytlsCmdSettings            byte = 4
	anytlsCmdAlert               byte = 5
	anytlsCmdUpdatePaddingScheme byte = 6
	anytlsCmdSYNACK              byte = 7
	anytlsCmdHeartRequest        byte = 8
	anytlsCmdHeartResponse       byte = 9
	anytlsCmdServerSettings      byte = 10

	uotMagicV2     = "sp.v2.udp-over-tcp.arpa"
	uotMagicLegacy = "sp.udp-over-tcp.arpa"
)

// handleAnyTLS implements the official AnyTLS v1 & v2 multiplexed session protocol:
// 1. Auth: `[sha256(password) (32B) | padding0_len (2B BE) | padding0]`
// 2. Session framing: `[cmd (1B) | streamId (4B BE) | dataLen (2B BE) | data]`
// 3. Supports `v=2` `cmdServerSettings` + `cmdSYNACK`, dynamic `paddingScheme` updates,
//    concurrent TCP streams (`SocksAddr`), and `sing-box` `sp.v2.udp-over-tcp.arpa` UDP relay.
func (s *Server) handleAnyTLS(conn net.Conn) {
	br := bufio.NewReaderSize(conn, 4096)

	var authHdr [34]byte
	if _, err := io.ReadFull(br, authHdr[:]); err != nil {
		return
	}

	var passHash [32]byte
	copy(passHash[:], authHdr[0:32])
	pad0Len := int(binary.BigEndian.Uint16(authHdr[32:34]))

	idx := s.userIdx.Load()
	if idx == nil {
		return
	}
	user := idx.BySHA256[passHash]
	if user == nil || user.IsDisabled() {
		return
	}

	if pad0Len > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(pad0Len)); err != nil {
			return
		}
	}
	_ = conn.SetDeadline(time.Time{})

	clientIP := relay.ExtractClientIP(conn.RemoteAddr())
	sessConnID, err := user.AcquireMuxSession(clientIP, s.tracker.IPTTLSeconds(), s.tracker.RedisLimiter(), conn)
	if err != nil {
		return
	}
	defer user.ReleaseMuxSession(sessConnID)

	sess := &anytlsSession{
		srv:     s,
		conn:    conn,
		user:    user,
		ctrlCh:  make(chan anytlsCtrlFrame, 64),
		doneCh:  make(chan struct{}),
		streams: make(map[uint32]*anytlsStream),
	}
	if scheme := strings.TrimSpace(s.spec.AnyTLSPaddingScheme); scheme != "" {
		sum := md5.Sum([]byte(scheme))
		sess.paddingScheme = []byte(scheme)
		sess.paddingMD5 = hex.EncodeToString(sum[:])
	}
	go sess.runCtrlWriter()
	defer sess.closeAllStreams()

	idleDur := time.Duration(s.cfg.ConnIdleSec) * time.Second
	if idleDur < 30*time.Second {
		idleDur = 120 * time.Second
	}

	var hdr [7]byte
	for {
		if user.IsDisabled() {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(idleDur))
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return
		}
		cmd := hdr[0]
		streamID := binary.BigEndian.Uint32(hdr[1:5])
		dataLen := int(binary.BigEndian.Uint16(hdr[5:7]))

		switch cmd {
		case anytlsCmdWaste:
			if dataLen > 0 {
				if _, err := io.CopyN(io.Discard, br, int64(dataLen)); err != nil {
					return
				}
			}

		case anytlsCmdSettings:
			var data []byte
			if dataLen > 0 {
				data = make([]byte, dataLen)
				if _, err := io.ReadFull(br, data); err != nil {
					return
				}
			}
			sess.seenSettings.Store(true)
			var clientVer int
			var clientPadMD5 string
			for _, line := range strings.Split(string(data), "\n") {
				k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
				if !ok {
					continue
				}
				switch strings.TrimSpace(k) {
				case "v":
					clientVer, _ = strconv.Atoi(strings.TrimSpace(v))
				case "padding-md5":
					clientPadMD5 = strings.ToLower(strings.TrimSpace(v))
				}
			}
			if clientVer >= 2 {
				sess.peerVersion.Store(int32(clientVer))
				sess.enqueueCtrl(anytlsCmdServerSettings, 0, []byte("v=2"))
			}
			if len(sess.paddingScheme) > 0 && clientPadMD5 != sess.paddingMD5 {
				sess.enqueueCtrl(anytlsCmdUpdatePaddingScheme, 0, sess.paddingScheme)
			}

		case anytlsCmdHeartRequest:
			if dataLen > 0 {
				if _, err := io.CopyN(io.Discard, br, int64(dataLen)); err != nil {
					return
				}
			}
			sess.enqueueCtrl(anytlsCmdHeartResponse, streamID, nil)

		case anytlsCmdHeartResponse:
			if dataLen > 0 {
				if _, err := io.CopyN(io.Discard, br, int64(dataLen)); err != nil {
					return
				}
			}

		case anytlsCmdSYN:
			if dataLen > 0 {
				if _, err := io.CopyN(io.Discard, br, int64(dataLen)); err != nil {
					return
				}
			}
			if !sess.seenSettings.Load() {
				sess.enqueueCtrl(anytlsCmdAlert, 0, []byte("cmdSettings required before cmdSYN"))
				return
			}
			st := sess.openStream(streamID)
			if st != nil {
				go sess.serveStream(st)
			}

		case anytlsCmdPSH:
			if dataLen == 0 {
				continue
			}
			payload := make([]byte, dataLen)
			if _, err := io.ReadFull(br, payload); err != nil {
				return
			}
			if st := sess.getStream(streamID); st != nil {
				st.pushRx(payload)
			}

		case anytlsCmdFIN:
			if dataLen > 0 {
				if _, err := io.CopyN(io.Discard, br, int64(dataLen)); err != nil {
					return
				}
			}
			sess.finFromPeer(streamID)

		default:
			if dataLen > 0 {
				if _, err := io.CopyN(io.Discard, br, int64(dataLen)); err != nil {
					return
				}
			}
		}
	}
}

type anytlsCtrlFrame struct {
	cmd      byte
	streamID uint32
	data     []byte
}

type anytlsSession struct {
	srv           *Server
	conn          net.Conn
	user          *stats.UserEntry
	paddingScheme []byte
	paddingMD5    string

	seenSettings atomic.Bool
	peerVersion  atomic.Int32
	closed       atomic.Bool
	closeOnce    sync.Once

	ctrlCh chan anytlsCtrlFrame
	doneCh chan struct{}

	writeMu sync.Mutex

	streamsMu sync.RWMutex
	streams   map[uint32]*anytlsStream
}

func (s *anytlsSession) enqueueCtrl(cmd byte, streamID uint32, data []byte) {
	if s.closed.Load() {
		return
	}
	select {
	case s.ctrlCh <- anytlsCtrlFrame{cmd: cmd, streamID: streamID, data: data}:
	default:
		// Control queue saturated (stalled peer) -> close session cleanly rather than deadlocking reader!
		s.closed.Store(true)
		_ = s.conn.Close()
	}
}

func (s *anytlsSession) runCtrlWriter() {
	for {
		select {
		case <-s.doneCh:
			return
		case f := <-s.ctrlCh:
			if err := s.writeFrame(f.cmd, f.streamID, f.data); err != nil {
				return
			}
		}
	}
}

func (s *anytlsSession) writeFrame(cmd byte, streamID uint32, data []byte) error {
	if s.closed.Load() {
		return net.ErrClosed
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}

	var hdr [7]byte
	hdr[0] = cmd
	binary.BigEndian.PutUint32(hdr[1:5], streamID)
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(data)))

	_ = s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	var err error
	if len(data) == 0 {
		_, err = s.conn.Write(hdr[:])
	} else {
		bufs := net.Buffers{hdr[:], data}
		_, err = bufs.WriteTo(s.conn)
	}
	if err != nil {
		// Prevent subsequent stream writes from injecting headers into a partially-written frame!
		s.closed.Store(true)
		_ = s.conn.Close()
	}
	return err
}

func (s *anytlsSession) openStream(id uint32) *anytlsStream {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	if s.closed.Load() || len(s.streams) >= 1024 {
		return nil
	}
	if _, dup := s.streams[id]; dup {
		return nil
	}
	st := newAnyTLSStream(s, id)
	s.streams[id] = st
	return st
}

func (s *anytlsSession) getStream(id uint32) *anytlsStream {
	s.streamsMu.RLock()
	st := s.streams[id]
	s.streamsMu.RUnlock()
	return st
}

func (s *anytlsSession) removeStream(st *anytlsStream) {
	s.streamsMu.Lock()
	if s.streams[st.id] == st {
		delete(s.streams, st.id)
	}
	s.streamsMu.Unlock()
}

func (s *anytlsSession) finFromPeer(id uint32) {
	s.streamsMu.Lock()
	st := s.streams[id]
	delete(s.streams, id)
	s.streamsMu.Unlock()
	if st != nil {
		st.markPeerEOF()
	}
}

func (s *anytlsSession) closeAllStreams() {
	s.closed.Store(true)
	s.closeOnce.Do(func() {
		close(s.doneCh)
	})
	s.streamsMu.Lock()
	list := make([]*anytlsStream, 0, len(s.streams))
	for _, st := range s.streams {
		list = append(list, st)
	}
	s.streams = make(map[uint32]*anytlsStream)
	s.streamsMu.Unlock()

	for _, st := range list {
		st.markPeerEOF()
	}
}

func (s *anytlsSession) serveStream(st *anytlsStream) {
	defer st.Close()

	if err := s.user.AcquireSubStream(); err != nil {
		if s.peerVersion.Load() >= 2 {
			s.enqueueCtrl(anytlsCmdSYNACK, st.id, []byte(err.Error()))
		}
		return
	}
	defer s.user.ReleaseSubStream()

	_ = st.SetReadDeadline(time.Now().Add(12 * time.Second))
	destHost, destPort, err := parseSOCKS5Addr(st)
	if err != nil {
		if s.peerVersion.Load() >= 2 {
			s.enqueueCtrl(anytlsCmdSYNACK, st.id, []byte("invalid destination address"))
		}
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	if destHost == uotMagicV2 || destHost == uotMagicLegacy {
		if s.peerVersion.Load() >= 2 {
			_ = s.writeFrame(anytlsCmdSYNACK, st.id, nil)
		}
		s.handleUoTStream(st, destHost == uotMagicV2)
		return
	}

	// Pre-check ACL on destination host/port so blocked targets receive clean v2 SYNACK error immediately
	aclEng := s.srv.aclEng.Load()
	preRoute := aclEng.DecideForNode(s.srv.cfg.NodeID, destHost, destPort, "", "")
	if preRoute.Action == acl.ActionBlock {
		if s.peerVersion.Load() >= 2 {
			_ = s.writeFrame(anytlsCmdSYNACK, st.id, []byte("blocked by audit policy"))
		}
		return
	}

	// Acknowledge stream (v=2) BEFORE peeking so AnyTLS v2 clients transmit their first payload
	// (TLS ClientHello / HTTP / BitTorrent), enabling full SNI unlock & BitTorrent blocking on both v1 and v2!
	if s.peerVersion.Load() >= 2 {
		if err := s.writeFrame(anytlsCmdSYNACK, st.id, nil); err != nil {
			return
		}
	}

	peeked, perr := s.srv.peekInitialPayload(st)
	if perr != nil {
		return
	}
	sn := sniff.Inspect(peeked)
	route := aclEng.DecideForNode(s.srv.cfg.NodeID, destHost, destPort, sn.Domain, sn.Protocol)
	if route.Action == acl.ActionBlock {
		return
	}

	effectiveHost := destHost
	if sn.Domain != "" && s.srv.cfg.DomainSniff {
		if _, isIP := netip.ParseAddr(destHost); isIP == nil {
			if s.srv.cfg.ForceDomainSniff || route.IsRemoteProxy || s.srv.dnsRes.HasRuleForDomain(sn.Domain) || aclEng.HasRouteForDomain(sn.Domain) {
				effectiveHost = sn.Domain
			}
		}
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	remoteConn, derr := relay.DialOutbound(dialCtx, effectiveHost, destPort, route, s.srv.dnsRes, 10*time.Second)
	cancel()
	if derr != nil {
		return
	}
	defer remoteConn.Close()

	idleDur := time.Duration(s.srv.cfg.ConnIdleSec) * time.Second
	if idleDur < 15*time.Second {
		idleDur = 120 * time.Second
	}
	relay.PipeBidirectional(st, remoteConn, peeked, s.user, s.srv.tracker.NodeLimiter, idleDur, false)
}

// handleUoTStream implements `sing-box` UDP-over-TCP v1 & v2 (`sp.v2.udp-over-tcp.arpa`) over an AnyTLS stream.
func (s *anytlsSession) handleUoTStream(st *anytlsStream, isV2 bool) {
	var isConnect bool
	var fixedHost string
	var fixedPort uint16

	if isV2 {
		var hdr [1]byte
		if _, err := io.ReadFull(st, hdr[:]); err != nil {
			return
		}
		isConnect = hdr[0] != 0
		var err error
		fixedHost, fixedPort, err = parseSOCKS5Addr(st)
		if err != nil {
			return
		}
	}

	var initRoute acl.OutboundTarget
	if isConnect && fixedHost != "" {
		initRoute = s.srv.aclEng.Load().DecideForNode(s.srv.cfg.NodeID, fixedHost, fixedPort, "", "")
		if initRoute.Action == acl.ActionBlock {
			return
		}
	} else {
		initRoute = s.srv.aclEng.Load().DecideForNode(s.srv.cfg.NodeID, "1.1.1.1", 443, "", "")
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	udpConn, err := relay.DialUDPForRoute(dctx, initRoute, false, s.srv.dnsRes)
	dcancel()
	if err != nil {
		return
	}
	defer udpConn.Close()

	idleDur := time.Duration(s.srv.cfg.UDPIdleSec) * time.Second
	if idleDur < 10*time.Second {
		idleDur = 60 * time.Second
	}

	var lastActive atomic.Int64
	lastActive.Store(time.Now().Unix())

	done := make(chan struct{})
	go func() {
		defer close(done)
		bp := bufpool.Get(bufpool.MaxUDPSize)
		buf := *bp
		defer bufpool.Put(bp)

		for {
			if s.user.IsDisabled() {
				return
			}
			_ = udpConn.SetReadDeadline(time.Now().Add(idleDur))
			n, raddr, rerr := udpConn.ReadFrom(buf)
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
			if ul := s.user.EffectiveLimiter(); ul != nil {
				ul.Wait(n)
			}
			s.srv.tracker.NodeLimiter.Wait(n)
			s.user.AddDownload(int64(n))

			var frame bytes.Buffer
			if !isConnect {
				writeUoTAddr(&frame, ua)
			}
			var l2 [2]byte
			binary.BigEndian.PutUint16(l2[:], uint16(n))
			frame.Write(l2[:])
			frame.Write(buf[:n])
			if _, werr := st.Write(frame.Bytes()); werr != nil {
				return
			}
		}
	}()

	bp := bufpool.Get(bufpool.MaxUDPSize)
	inBuf := *bp
	defer bufpool.Put(bp)

	for {
		if s.user.IsDisabled() {
			break
		}
		_ = st.SetReadDeadline(time.Now().Add(idleDur))
		host, port := fixedHost, fixedPort
		var l2 [2]byte
		if !isConnect {
			// Read the first byte (address family) separately so we only retry on timeout
			// when 0 bytes of the frame were consumed; any mid-frame timeout breaks cleanly.
			var af [1]byte
			rn, rerr := st.Read(af[:])
			if rn == 0 {
				if errors.Is(rerr, context.DeadlineExceeded) && time.Since(time.Unix(lastActive.Load(), 0)) < idleDur {
					continue
				}
				break
			}
			var aerr error
			host, port, aerr = readUoTAddrWithAF(st, af[0])
			if aerr != nil {
				break
			}
			if _, err := io.ReadFull(st, l2[:]); err != nil {
				break
			}
		} else {
			rn, rerr := st.Read(l2[:1])
			if rn == 0 {
				if errors.Is(rerr, context.DeadlineExceeded) && time.Since(time.Unix(lastActive.Load(), 0)) < idleDur {
					continue
				}
				break
			}
			if _, err := io.ReadFull(st, l2[1:]); err != nil {
				break
			}
		}
		pktLen := int(binary.BigEndian.Uint16(l2[:]))
		if pktLen > len(inBuf) {
			break
		}
		if pktLen > 0 {
			if _, err := io.ReadFull(st, inBuf[:pktLen]); err != nil {
				break
			}
		}
		lastActive.Store(time.Now().Unix())

		route := s.srv.aclEng.Load().DecideForNode(s.srv.cfg.NodeID, host, port, "", "")
		if route.Action == acl.ActionBlock {
			continue
		}
		rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
		dstAddr, err := relay.ResolveUDPTargetForRoute(rctx, host, port, route, s.srv.dnsRes)
		rcancel()
		if err != nil {
			continue
		}

		if ul := s.user.EffectiveLimiter(); ul != nil {
			ul.Wait(pktLen)
		}
		s.srv.tracker.NodeLimiter.Wait(pktLen)
		s.user.AddUpload(int64(pktLen))
		_, _ = udpConn.WriteTo(inBuf[:pktLen], dstAddr)
	}

	_ = udpConn.Close()
	<-done
}

func readUoTAddr(r io.Reader) (string, uint16, error) {
	var af [1]byte
	if _, err := io.ReadFull(r, af[:]); err != nil {
		return "", 0, err
	}
	return readUoTAddrWithAF(r, af[0])
}

func readUoTAddrWithAF(r io.Reader, af byte) (string, uint16, error) {
	var host string
	switch af {
	case 0x00: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(ip[:]).String()
	case 0x01: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(ip[:]).String()
	case 0x02: // FQDN
		var dl [1]byte
		if _, err := io.ReadFull(r, dl[:]); err != nil {
			return "", 0, err
		}
		d := make([]byte, int(dl[0]))
		if _, err := io.ReadFull(r, d); err != nil {
			return "", 0, err
		}
		host = string(d)
	default:
		return "", 0, errors.New("invalid uot address family")
	}
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(pb[:]), nil
}

func writeUoTAddr(w *bytes.Buffer, ua *net.UDPAddr) {
	if ip4 := ua.IP.To4(); ip4 != nil {
		w.WriteByte(0x00)
		w.Write(ip4)
	} else {
		w.WriteByte(0x01)
		w.Write(ua.IP.To16())
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(ua.Port))
	w.Write(pb[:])
}

type anytlsStream struct {
	sess       *anytlsSession
	id         uint32
	needSYNACK atomic.Bool

	rxMu       sync.Mutex
	rxCond     *sync.Cond
	rxBuf      bytes.Buffer
	peerEOF    bool
	localClose bool
	readTimer  *time.Timer
	timerGen   uint64 // generation counter to invalidate stale AfterFunc callbacks
	timedOut   bool

	finOnce sync.Once
}

func newAnyTLSStream(sess *anytlsSession, id uint32) *anytlsStream {
	st := &anytlsStream{
		sess: sess,
		id:   id,
	}
	st.rxCond = sync.NewCond(&st.rxMu)
	return st
}

func (s *anytlsStream) pushRx(data []byte) {
	var overflow bool
	s.rxMu.Lock()
	if !s.peerEOF && !s.localClose {
		// Cap per-stream unread buffer at 256 KiB; abort stream cleanly on overflow instead of silently corrupting middle bytes!
		if s.rxBuf.Len()+len(data) <= 256*1024 {
			_, _ = s.rxBuf.Write(data)
		} else {
			s.peerEOF = true
			s.localClose = true
			s.rxBuf.Reset()
			overflow = true
		}
	}
	s.rxCond.Broadcast()
	s.rxMu.Unlock()
	if overflow {
		s.sess.removeStream(s)
		s.sess.enqueueCtrl(anytlsCmdFIN, s.id, nil)
	}
}

func (s *anytlsStream) markPeerEOF() {
	s.rxMu.Lock()
	s.peerEOF = true
	s.rxCond.Broadcast()
	s.rxMu.Unlock()
}

func (s *anytlsStream) Read(p []byte) (int, error) {
	s.rxMu.Lock()
	defer s.rxMu.Unlock()

	for s.rxBuf.Len() == 0 {
		if s.localClose {
			return 0, net.ErrClosed
		}
		if s.peerEOF {
			return 0, io.EOF
		}
		if s.timedOut {
			return 0, context.DeadlineExceeded
		}
		s.rxCond.Wait()
	}
	n, err := s.rxBuf.Read(p)
	if s.rxBuf.Len() == 0 && s.rxBuf.Cap() > 16384 {
		s.rxBuf = bytes.Buffer{}
	}
	return n, err
}

func (s *anytlsStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	const maxChunk = 32768
	for len(p) > 0 {
		part := p
		if len(part) > maxChunk {
			part = p[:maxChunk]
		}
		p = p[len(part):]
		if err := s.sess.writeFrame(anytlsCmdPSH, s.id, part); err != nil {
			return total, err
		}
		total += len(part)
	}
	return total, nil
}

// sendFINOnce transmits `anytlsCmdFIN` when closing locally if peer has not already sent `cmdFIN`.
// Note: `anytlsStream` intentionally does NOT implement `CloseWrite()` because per AnyTLS spec,
// `cmdFIN` is a non-echoed full close (implementing `CloseWrite()` caused 15s-300s hangs on server EOF).
func (s *anytlsStream) sendFINOnce() {
	s.finOnce.Do(func() {
		s.rxMu.Lock()
		gotPeerFIN := s.peerEOF
		s.rxMu.Unlock()
		if !gotPeerFIN && !s.sess.closed.Load() {
			s.sess.enqueueCtrl(anytlsCmdFIN, s.id, nil)
		}
	})
}

func (s *anytlsStream) Close() error {
	s.sendFINOnce()
	s.sess.removeStream(s)
	s.rxMu.Lock()
	s.localClose = true
	if s.readTimer != nil {
		s.readTimer.Stop()
	}
	s.rxBuf.Reset()
	s.rxCond.Broadcast()
	s.rxMu.Unlock()
	return nil
}

func (s *anytlsStream) LocalAddr() net.Addr  { return s.sess.conn.LocalAddr() }
func (s *anytlsStream) RemoteAddr() net.Addr { return s.sess.conn.RemoteAddr() }

func (s *anytlsStream) SetDeadline(t time.Time) error {
	return s.SetReadDeadline(t)
}

func (s *anytlsStream) SetReadDeadline(t time.Time) error {
	s.rxMu.Lock()
	defer s.rxMu.Unlock()
	if s.readTimer != nil {
		s.readTimer.Stop()
		s.readTimer = nil
	}
	s.timerGen++ // invalidate any in-flight AfterFunc callback
	s.timedOut = false
	if t.IsZero() {
		return nil
	}
	dur := time.Until(t)
	if dur <= 0 {
		s.timedOut = true
		s.rxCond.Broadcast()
		return nil
	}
	gen := s.timerGen
	s.readTimer = time.AfterFunc(dur, func() {
		s.rxMu.Lock()
		if s.timerGen == gen { // only fire if no newer SetReadDeadline has been called
			s.timedOut = true
			s.rxCond.Broadcast()
		}
		s.rxMu.Unlock()
	})
	return nil
}

func (s *anytlsStream) SetWriteDeadline(_ time.Time) error { return nil }
