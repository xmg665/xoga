package protocol

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/crypto/blake2b"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/logger"
	"github.com/xmg665/xoga/internal/relay"
	"github.com/xmg665/xoga/internal/sniff"
	"github.com/xmg665/xoga/internal/stats"
	"github.com/xmg665/xoga/internal/transport"
)

const (
	hy2FrameTCPRequest = 0x401
	hy2StatusAuthOK    = 233
	hy2MaxAddrLen      = 2048
	hy2MaxPadLen       = 4096
	hy2SalamanderSalt  = 8
)

type hy2QuicCloser struct {
	qconn *quic.Conn
}

func (c *hy2QuicCloser) Close() error {
	return c.qconn.CloseWithError(0, "user session terminated")
}

// startHysteria2 starts a QUIC + HTTP/3 Hysteria 2 server supporting:
// - HTTP/3 `/auth` (`233 HyOK`) + active-probing HTTP/3 `404` web server masquerade
// - Optional Salamander UDP packet obfuscation (`obfs=salamander`)
// - `0x401` bidirectional QUIC TCP proxy streams with SNI sniffing & ACL routing
// - RFC 9221 QUIC Datagram UDP relay with multi-fragment reassembly & instant user kick
func (s *Server) startHysteria2(addr string) error {
	rawUDP, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("listen hysteria2 udp %s: %w", addr, err)
	}

	pktConn := rawUDP
	if s.spec.Hy2Obfs == "salamander" && s.spec.Hy2ObfsPassword != "" {
		obfsConn, oerr := newSalamanderPacketConn(rawUDP, []byte(s.spec.Hy2ObfsPassword))
		if oerr != nil {
			_ = rawUDP.Close()
			return fmt.Errorf("init hysteria2 salamander obfs: %w", oerr)
		}
		pktConn = obfsConn
	}
	s.udpConn = pktConn

	tp, err := transport.BuildTLSConfigWithALPN(s.cfg, s.spec.ServerName, []string{http3.NextProtoH3})
	if err != nil {
		_ = pktConn.Close()
		return fmt.Errorf("init hysteria2 TLS: %w", err)
	}
	s.tlsProv = tp
	tlsCfg := tp.Config().Clone()
	tlsCfg.MinVersion = tls.VersionTLS13
	tlsCfg.NextProtos = []string{http3.NextProtoH3}

	idleDur := time.Duration(s.cfg.ConnIdleSec) * time.Second
	if idleDur < 30*time.Second {
		idleDur = 120 * time.Second
	}

	qtr := &quic.Transport{Conn: pktConn}
	qln, err := qtr.Listen(tlsCfg, &quic.Config{
		EnableDatagrams:       true,
		MaxIncomingStreams:    1024,
		MaxIncomingUniStreams: 256,
		MaxIdleTimeout:        idleDur,
		KeepAlivePeriod:       15 * time.Second,
	})
	if err != nil {
		_ = qtr.Close()
		_ = pktConn.Close()
		return fmt.Errorf("listen hysteria2 quic %s: %w", addr, err)
	}
	s.hy2Transport = qtr
	s.hy2Listener = qln

	s.wg.Add(1)
	go s.acceptHysteria2Loop(qln)

	logger.Infof("Inbound started: protocol=hysteria2 addr=%s/udp obfs=%s sni=%s",
		addr, emptyOrNone(s.spec.Hy2Obfs), s.spec.ServerName)
	return nil
}

func emptyOrNone(v string) string {
	if v == "" {
		return "none"
	}
	return v
}

func (s *Server) acceptHysteria2Loop(qln *quic.Listener) {
	defer s.wg.Done()
	for {
		qconn, err := qln.Accept(context.Background())
		if err != nil {
			if s.closed.Load() {
				return
			}
			continue
		}
		go s.handleHy2Conn(qconn)
	}
}

type hy2ConnState struct {
	srv        *Server
	qconn      *quic.Conn
	clientIP   netip.Addr
	authMu     sync.Mutex
	authed     atomic.Bool
	user       *stats.UserEntry
	sessConnID uint64
	udpOnce    sync.Once
}

func (h *hy2ConnState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && strings.EqualFold(r.Host, "hysteria") && r.URL.Path == "/auth" {
		h.authMu.Lock()
		defer h.authMu.Unlock()

		if h.authed.Load() && h.user != nil && !h.user.IsDisabled() {
			h.writeAuthOK(w)
			return
		}

		cred := strings.TrimSpace(r.Header.Get("Hysteria-Auth"))
		idx := h.srv.userIdx.Load()
		var user *stats.UserEntry
		if idx != nil && cred != "" {
			user = idx.LookupPassword(cred)
		}
		if user == nil || user.IsDisabled() {
			http.NotFound(w, r)
			return
		}

		cid, err := user.AcquireSession(h.clientIP, h.srv.tracker.IPTTLSeconds(), h.srv.tracker.RedisLimiter(), &hy2QuicCloser{qconn: h.qconn})
		if err != nil {
			http.NotFound(w, r)
			return
		}

		h.user = user
		h.sessConnID = cid
		h.authed.Store(true)
		h.writeAuthOK(w)

		h.udpOnce.Do(func() {
			go h.serveDatagrams()
		})
		return
	}

	// Standard HTTP/3 masquerade response for unauthenticated active probers
	w.Header().Set("Server", "nginx")
	http.NotFound(w, r)
}

func (h *hy2ConnState) writeAuthOK(w http.ResponseWriter) {
	w.Header().Set("Hysteria-UDP", "true")
	if h.srv.spec.Hy2IgnoreClientBW || h.srv.spec.Hy2DownMbps <= 0 {
		w.Header().Set("Hysteria-CC-RX", "auto")
	} else {
		w.Header().Set("Hysteria-CC-RX", strconv.FormatUint(uint64(h.srv.spec.Hy2DownMbps)*125000, 10))
	}
	w.Header().Set("Hysteria-Padding", randomASCIIPadding(32, 96))
	w.WriteHeader(hy2StatusAuthOK)
}

func (s *Server) handleHy2Conn(qconn *quic.Conn) {
	state := &hy2ConnState{
		srv:      s,
		qconn:    qconn,
		clientIP: relay.ExtractClientIP(qconn.RemoteAddr()),
	}
	defer func() {
		_ = qconn.CloseWithError(0, "")
		state.authMu.Lock()
		u := state.user
		cid := state.sessConnID
		state.user = nil
		state.sessConnID = 0
		state.authMu.Unlock()
		if u != nil {
			u.ReleaseSession(cid)
		}
	}()

	// IMPORTANT: EnableDatagrams MUST stay false on `http3.Server` (while true on `quic.Config`)!
	// Hysteria 2 exchanges raw RFC 9221 QUIC Datagrams directly on `qconn`, whereas `http3.Server.EnableDatagrams`
	// spawns an internal RFC 9297 HTTP/3 datagram reader that would consume raw QUIC datagrams.
	h3Srv := &http3.Server{
		Handler:           state,
		EnableDatagrams:   false,
		ReadHeaderTimeout: 10 * time.Second,
	}
	rawH3, err := h3Srv.NewRawServerConn(qconn)
	if err != nil {
		return
	}

	ctx := qconn.Context()
	go func() {
		for {
			uni, uerr := qconn.AcceptUniStream(ctx)
			if uerr != nil {
				return
			}
			go rawH3.HandleUnidirectionalStream(uni)
		}
	}()

	for {
		str, serr := qconn.AcceptStream(ctx)
		if serr != nil {
			return
		}
		if !state.authed.Load() {
			go rawH3.HandleRequestStream(str)
			continue
		}
		go state.handleTCPStream(str)
	}
}

func (h *hy2ConnState) handleTCPStream(qstr *quic.Stream) {
	sc := &hy2StreamConn{
		Stream:     qstr,
		localAddr:  h.qconn.LocalAddr(),
		remoteAddr: h.qconn.RemoteAddr(),
	}
	defer sc.Close()

	user := h.user
	if user == nil || user.IsDisabled() {
		return
	}

	_ = sc.SetReadDeadline(time.Now().Add(12 * time.Second))
	vr := quicvarint.NewReader(sc)
	ft, err := quicvarint.Read(vr)
	if err != nil || ft != hy2FrameTCPRequest {
		return
	}
	addrStr, err := readHy2TCPRequest(sc, vr)
	if err != nil {
		return
	}
	host, portStr, err := net.SplitHostPort(addrStr)
	if err != nil {
		_ = writeHy2TCPResponse(sc, false, "invalid target address")
		return
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum <= 0 || portNum > 65535 {
		_ = writeHy2TCPResponse(sc, false, "invalid target port")
		return
	}
	destPort := uint16(portNum)
	_ = sc.SetReadDeadline(time.Time{})

	// Pre-check ACL before dialing so blocked targets receive clean Hysteria error status
	aclEng := h.srv.aclEng.Load()
	preRoute := aclEng.DecideForNode(h.srv.cfg.NodeID, host, destPort, "", "")
	if preRoute.Action == acl.ActionBlock {
		_ = writeHy2TCPResponse(sc, false, "blocked by policy")
		return
	}

	// Send Hysteria 2 TCPResponse OK immediately so client sends its first payload (TLS ClientHello / HTTP)
	if err := writeHy2TCPResponse(sc, true, ""); err != nil {
		return
	}

	// Peek initial payload for SNI / HTTP / BitTorrent sniffing
	var peeked []byte
	peekBuf := bufpool.Get(bufpool.SmallSize)
	defer bufpool.Put(peekBuf)
	_ = sc.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	n, rerr := sc.Read((*peekBuf)[:])
	_ = sc.SetReadDeadline(time.Time{})
	if n > 0 {
		peeked = (*peekBuf)[:n]
	} else if rerr != nil {
		var ne net.Error
		if !errors.As(rerr, &ne) || !ne.Timeout() {
			return
		}
	}

	sn := sniff.Inspect(peeked)
	route := aclEng.DecideForNode(h.srv.cfg.NodeID, host, destPort, sn.Domain, sn.Protocol)
	if route.Action == acl.ActionBlock {
		return
	}

	effectiveHost := host
	if sn.Domain != "" && h.srv.cfg.DomainSniff {
		if _, isIP := netip.ParseAddr(host); isIP == nil {
			if h.srv.cfg.ForceDomainSniff || route.Action == acl.ActionProxy || h.srv.dnsRes.HasRuleForDomain(sn.Domain) || aclEng.HasRouteForDomain(sn.Domain) {
				effectiveHost = sn.Domain
			}
		}
	}

	dialCtx, cancel := context.WithTimeout(h.qconn.Context(), 10*time.Second)
	remoteConn, err := relay.DialOutbound(dialCtx, effectiveHost, destPort, route, h.srv.dnsRes, 10*time.Second)
	cancel()
	if err != nil {
		return
	}
	defer remoteConn.Close()

	idleDur := time.Duration(h.srv.cfg.ConnIdleSec) * time.Second
	if idleDur < 15*time.Second {
		idleDur = 120 * time.Second
	}
	relay.PipeBidirectional(sc, remoteConn, peeked, user, h.srv.tracker.NodeLimiter, idleDur, false)
}

type hy2UDPSess struct {
	udpConn  *net.UDPConn
	lastSeen atomic.Int64
	lastAddr string
}

type hy2FragAssembly struct {
	pktID   uint16
	count   uint8
	got     uint8
	addr    string
	parts   [][]byte
	created time.Time
}

func (h *hy2ConnState) serveDatagrams() {
	user := h.user
	if user == nil {
		return
	}
	idleDur := time.Duration(h.srv.cfg.UDPIdleSec) * time.Second
	if idleDur < 10*time.Second {
		idleDur = 60 * time.Second
	}

	var mu sync.Mutex
	sessions := make(map[uint32]*hy2UDPSess)
	frags := make(map[uint32]*hy2FragAssembly)
	var outPktID atomic.Uint32

	defer func() {
		mu.Lock()
		for _, us := range sessions {
			_ = us.udpConn.Close()
		}
		sessions = nil
		mu.Unlock()
	}()

	ctx := h.qconn.Context()
	for {
		if user.IsDisabled() {
			_ = h.qconn.CloseWithError(0, "quota/account expired")
			return
		}
		dgram, err := h.qconn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		sessID, pktID, fragID, fragCnt, addrStr, payload, perr := parseHy2UDPMessage(dgram)
		if perr != nil || fragCnt == 0 {
			continue
		}

		if fragCnt > 1 {
			if fragID >= fragCnt || fragCnt > 32 {
				continue
			}
			mu.Lock()
			fa, ok := frags[sessID]
			if !ok || fa.pktID != pktID || fa.count != fragCnt || time.Since(fa.created) > 5*time.Second {
				fa = &hy2FragAssembly{
					pktID:   pktID,
					count:   fragCnt,
					addr:    addrStr,
					parts:   make([][]byte, fragCnt),
					created: time.Now(),
				}
				frags[sessID] = fa
			}
			if fa.parts[fragID] == nil {
				cp := make([]byte, len(payload))
				copy(cp, payload)
				fa.parts[fragID] = cp
				fa.got++
			}
			if addrStr != "" {
				fa.addr = addrStr
			}
			if fa.got < fa.count {
				mu.Unlock()
				continue
			}
			var totalLen int
			for _, p := range fa.parts {
				totalLen += len(p)
			}
			merged := make([]byte, 0, totalLen)
			for _, p := range fa.parts {
				merged = append(merged, p...)
			}
			addrStr = fa.addr
			payload = merged
			delete(frags, sessID)
			mu.Unlock()
		}

		host, portStr, err := net.SplitHostPort(addrStr)
		if err != nil {
			continue
		}
		portNum, err := strconv.Atoi(portStr)
		if err != nil || portNum <= 0 || portNum > 65535 {
			continue
		}

		route := h.srv.aclEng.Load().DecideForNode(h.srv.cfg.NodeID, host, uint16(portNum), "", "")
		if route.Action == acl.ActionBlock {
			continue
		}

		rctx, rcancel := context.WithTimeout(ctx, 3*time.Second)
		dstUDP, err := relay.ResolveUDPTargetForRoute(rctx, host, uint16(portNum), route, h.srv.dnsRes)
		rcancel()
		if err != nil {
			continue
		}

		mu.Lock()
		us, exists := sessions[sessID]
		if !exists {
			if len(sessions) >= 512 {
				mu.Unlock()
				continue
			}
			localUDP := relay.LocalUDPAddrForRoute(route, false)
			uconn, lerr := net.ListenUDP("udp", localUDP)
			if lerr != nil {
				mu.Unlock()
				continue
			}
			us = &hy2UDPSess{udpConn: uconn, lastAddr: addrStr}
			us.lastSeen.Store(time.Now().Unix())
			sessions[sessID] = us

			go func(sid uint32, sess *hy2UDPSess) {
				defer func() {
					_ = sess.udpConn.Close()
					mu.Lock()
					if sessions != nil && sessions[sid] == sess {
						delete(sessions, sid)
					}
					mu.Unlock()
				}()
				bp := bufpool.Get(bufpool.MaxUDPSize)
				buf := *bp
				defer bufpool.Put(bp)

				for {
					if user.IsDisabled() {
						return
					}
					_ = sess.udpConn.SetReadDeadline(time.Now().Add(idleDur))
					rn, raddr, rerr := sess.udpConn.ReadFromUDP(buf)
					if rerr != nil {
						return
					}
					sess.lastSeen.Store(time.Now().Unix())
					if ul := user.EffectiveLimiter(); ul != nil {
						ul.Wait(rn)
					}
					h.srv.tracker.NodeLimiter.Wait(rn)
					user.AddDownload(int64(rn))

					srcStr := raddr.String()
					pid := uint16(outPktID.Add(1))
					sendHy2UDPDatagrams(h.qconn, sid, pid, srcStr, buf[:rn])
				}
			}(sessID, us)
		} else {
			us.lastSeen.Store(time.Now().Unix())
		}
		mu.Unlock()

		if ul := user.EffectiveLimiter(); ul != nil {
			ul.Wait(len(payload))
		}
		h.srv.tracker.NodeLimiter.Wait(len(payload))
		user.AddUpload(int64(len(payload)))
		_, _ = us.udpConn.WriteToUDP(payload, dstUDP)
	}
}

func sendHy2UDPDatagrams(qconn *quic.Conn, sessID uint32, pktID uint16, addr string, data []byte) {
	const maxFragPayload = 1100
	if len(data) <= maxFragPayload {
		frame := encodeHy2UDPMessage(sessID, pktID, 0, 1, addr, data)
		_ = qconn.SendDatagram(frame)
		return
	}
	fragCnt := (len(data) + maxFragPayload - 1) / maxFragPayload
	if fragCnt > 255 {
		return
	}
	for i := 0; i < fragCnt; i++ {
		start := i * maxFragPayload
		end := start + maxFragPayload
		if end > len(data) {
			end = len(data)
		}
		frame := encodeHy2UDPMessage(sessID, pktID, uint8(i), uint8(fragCnt), addr, data[start:end])
		if err := qconn.SendDatagram(frame); err != nil {
			return
		}
	}
}

func encodeHy2UDPMessage(sessID uint32, pktID uint16, fragID, fragCnt uint8, addr string, data []byte) []byte {
	addrBytes := []byte(addr)
	hdrCap := 8 + 4 + len(addrBytes) + len(data)
	out := make([]byte, 8, hdrCap)
	binary.BigEndian.PutUint32(out[0:4], sessID)
	binary.BigEndian.PutUint16(out[4:6], pktID)
	out[6] = fragID
	out[7] = fragCnt
	out = quicvarint.Append(out, uint64(len(addrBytes)))
	out = append(out, addrBytes...)
	out = append(out, data...)
	return out
}

func parseHy2UDPMessage(msg []byte) (sessID uint32, pktID uint16, fragID, fragCnt uint8, addr string, data []byte, err error) {
	if len(msg) < 9 {
		return 0, 0, 0, 0, "", nil, io.ErrUnexpectedEOF
	}
	sessID = binary.BigEndian.Uint32(msg[0:4])
	pktID = binary.BigEndian.Uint16(msg[4:6])
	fragID = msg[6]
	fragCnt = msg[7]
	addrLen, n, err := quicvarint.Parse(msg[8:])
	if err != nil || addrLen == 0 || addrLen > hy2MaxAddrLen {
		return 0, 0, 0, 0, "", nil, errors.New("invalid hy2 udp addr len")
	}
	rest := msg[8+n:]
	if len(rest) < int(addrLen) {
		return 0, 0, 0, 0, "", nil, io.ErrUnexpectedEOF
	}
	addr = string(rest[:addrLen])
	data = rest[addrLen:]
	return sessID, pktID, fragID, fragCnt, addr, data, nil
}

func readHy2TCPRequest(r io.Reader, vr quicvarint.Reader) (string, error) {
	addrLen, err := quicvarint.Read(vr)
	if err != nil || addrLen == 0 || addrLen > hy2MaxAddrLen {
		return "", errors.New("invalid hy2 tcp address length")
	}
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrBuf); err != nil {
		return "", err
	}
	padLen, err := quicvarint.Read(vr)
	if err != nil || padLen > hy2MaxPadLen {
		return "", errors.New("invalid hy2 tcp padding length")
	}
	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return "", err
		}
	}
	return string(addrBuf), nil
}

func writeHy2TCPResponse(w io.Writer, ok bool, msg string) error {
	pad := randomASCIIPadding(16, 64)
	out := make([]byte, 0, 16+len(msg)+len(pad))
	if ok {
		out = append(out, 0x00)
	} else {
		out = append(out, 0x01)
	}
	out = quicvarint.Append(out, uint64(len(msg)))
	out = append(out, msg...)
	out = quicvarint.Append(out, uint64(len(pad)))
	out = append(out, pad...)
	_, err := w.Write(out)
	return err
}

func randomASCIIPadding(minLen, maxLen int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	span := maxLen - minLen
	if span <= 0 {
		span = 1
	}
	var rb [96]byte
	_, _ = rand.Read(rb[:])
	n := minLen + int(rb[0])%span
	if n > len(rb) {
		n = len(rb)
	}
	for i := 0; i < n; i++ {
		rb[i] = alphabet[int(rb[i])%len(alphabet)]
	}
	return string(rb[:n])
}

type hy2StreamConn struct {
	*quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *hy2StreamConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *hy2StreamConn) RemoteAddr() net.Addr { return c.remoteAddr }
func (c *hy2StreamConn) CloseWrite() error    { return c.Stream.Close() }
func (c *hy2StreamConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}

// salamanderPacketConn implements Hysteria 2 Salamander UDP obfuscation:
// wire packet = `[8-byte random salt][payload XOR BLAKE2b-256(psk || salt)]`.
type salamanderPacketConn struct {
	net.PacketConn
	psk []byte
}

func newSalamanderPacketConn(c net.PacketConn, psk []byte) (net.PacketConn, error) {
	if len(psk) < 4 {
		return nil, errors.New("salamander obfs password must be at least 4 bytes")
	}
	cp := append([]byte(nil), psk...)
	return &salamanderPacketConn{PacketConn: c, psk: cp}, nil
}

func (s *salamanderPacketConn) SetReadBuffer(bytes int) error {
	if uc, ok := s.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return uc.SetReadBuffer(bytes)
	}
	return nil
}

func (s *salamanderPacketConn) SetWriteBuffer(bytes int) error {
	if uc, ok := s.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return uc.SetWriteBuffer(bytes)
	}
	return nil
}

func (s *salamanderPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bp := bufpool.Get(bufpool.MaxUDPSize)
	raw := *bp
	defer bufpool.Put(bp)

	for {
		n, addr, err := s.PacketConn.ReadFrom(raw)
		if err != nil {
			return 0, nil, err
		}
		if n <= hy2SalamanderSalt {
			continue
		}
		key := s.deriveKey(raw[:hy2SalamanderSalt])
		payLen := n - hy2SalamanderSalt
		if payLen > len(p) {
			payLen = len(p)
		}
		src := raw[hy2SalamanderSalt : hy2SalamanderSalt+payLen]
		for i := 0; i < payLen; i++ {
			p[i] = src[i] ^ key[i&31]
		}
		return payLen, addr, nil
	}
}

func (s *salamanderPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	bp := bufpool.Get(hy2SalamanderSalt + len(p))
	out := (*bp)[:hy2SalamanderSalt+len(p)]
	defer bufpool.Put(bp)

	_, _ = rand.Read(out[:hy2SalamanderSalt])
	key := s.deriveKey(out[:hy2SalamanderSalt])
	for i := 0; i < len(p); i++ {
		out[hy2SalamanderSalt+i] = p[i] ^ key[i&31]
	}
	if _, err := s.PacketConn.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *salamanderPacketConn) deriveKey(salt []byte) [32]byte {
	var stackBuf [128]byte
	var in []byte
	if len(s.psk)+hy2SalamanderSalt <= len(stackBuf) {
		in = stackBuf[:len(s.psk)+hy2SalamanderSalt]
	} else {
		in = make([]byte, len(s.psk)+hy2SalamanderSalt)
	}
	copy(in, s.psk)
	copy(in[len(s.psk):], salt[:hy2SalamanderSalt])
	return blake2b.Sum256(in)
}
