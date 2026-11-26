package protocol

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/relay"
	"github.com/xmg665/xoga/internal/sniff"
	"github.com/xmg665/xoga/internal/stats"
)

type muxTCPSubSession struct {
	txCh     chan []byte
	txMu     sync.Mutex
	txClosed bool
	aborted  atomic.Bool

	connMu sync.Mutex
	remote net.Conn
}

func newMuxTCPSubSession() *muxTCPSubSession {
	return &muxTCPSubSession{
		txCh: make(chan []byte, 64),
	}
}

func (m *muxTCPSubSession) enqueue(data []byte) bool {
	if len(data) == 0 || m.aborted.Load() {
		return false
	}
	cp := make([]byte, len(data))
	copy(cp, data)

	m.txMu.Lock()
	if m.txClosed || m.aborted.Load() {
		m.txMu.Unlock()
		return false
	}
	select {
	case m.txCh <- cp:
		m.txMu.Unlock()
		return true
	default:
		// Sub-stream upload queue full -> block briefly under no mutex? Never hold txMu while blocking;
		// instead close sub-session cleanly only if peer stops draining completely.
		ch := m.txCh
		m.txMu.Unlock()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case ch <- cp:
			return true
		case <-timer.C:
			m.abort()
			return false
		}
	}
}

func (m *muxTCPSubSession) closeClientTx() {
	m.txMu.Lock()
	if !m.txClosed {
		m.txClosed = true
		close(m.txCh)
	}
	m.txMu.Unlock()
}

func (m *muxTCPSubSession) abort() {
	if m.aborted.CompareAndSwap(false, true) {
		m.closeClientTx()
		m.connMu.Lock()
		rc := m.remote
		m.connMu.Unlock()
		if rc != nil {
			_ = rc.Close()
		}
	}
}

func encodeMuxTCPReplyData(dst []byte, sid uint16, payload []byte) []byte {
	// [metaLen=4 (2B)][sid (2B)][status=0x02 Keep (1B)][opt=0x01 Data (1B)][dataLen (2B)][payload]
	total := 8 + len(payload)
	out := dst
	if cap(out) < total {
		out = make([]byte, total)
	} else {
		out = out[:total]
	}
	binary.BigEndian.PutUint16(out[0:2], 4)
	binary.BigEndian.PutUint16(out[2:4], sid)
	out[4] = 0x02 // SessionStatusKeep
	out[5] = 0x01 // OptionData
	binary.BigEndian.PutUint16(out[6:8], uint16(len(payload)))
	copy(out[8:], payload)
	return out
}

func encodeMuxTCPEndFrame(sid uint16, isErr bool) []byte {
	var out [6]byte
	binary.BigEndian.PutUint16(out[0:2], 4)
	binary.BigEndian.PutUint16(out[2:4], sid)
	out[4] = 0x03 // SessionStatusEnd
	if isErr {
		out[5] = 0x02 // OptionError
	} else {
		out[5] = 0x00
	}
	return out[:]
}

func (s *Server) runMuxTCPSubSession(
	sid uint16,
	destHost string,
	destPort uint16,
	user *stats.UserEntry,
	sub *muxTCPSubSession,
	writeFrame func([]byte) error,
	onDone func(),
) {
	defer func() {
		user.ReleaseSubStream()
		sub.abort()
		onDone()
	}()

	if user == nil || user.IsDisabled() {
		_ = writeFrame(encodeMuxTCPEndFrame(sid, true))
		return
	}

	// Peek first queued payload (up to 60ms if not already sent with SessionStatusNew) for SNI/HTTP domain sniffing
	var firstChunk []byte
	select {
	case b, ok := <-sub.txCh:
		if ok {
			firstChunk = b
		}
	case <-time.After(60 * time.Millisecond):
	}

	sn := sniff.Inspect(firstChunk)
	aclEng := s.aclEng.Load()
	route := aclEng.DecideForNode(s.cfg.NodeID, destHost, destPort, sn.Domain, sn.Protocol)
	if route.Action == acl.ActionBlock {
		_ = writeFrame(encodeMuxTCPEndFrame(sid, true))
		return
	}

	effectiveHost := destHost
	if sn.Domain != "" && s.cfg.DomainSniff {
		if _, isIP := netip.ParseAddr(destHost); isIP == nil {
			if s.cfg.ForceDomainSniff || route.IsRemoteProxy || s.dnsRes.HasRuleForDomain(sn.Domain) || aclEng.HasRouteForDomain(sn.Domain) {
				effectiveHost = sn.Domain
			}
		}
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	remoteConn, err := relay.DialOutbound(dialCtx, effectiveHost, destPort, route, s.dnsRes, 10*time.Second)
	cancel()
	if err != nil {
		_ = writeFrame(encodeMuxTCPEndFrame(sid, true))
		return
	}

	sub.connMu.Lock()
	if sub.aborted.Load() {
		sub.connMu.Unlock()
		_ = remoteConn.Close()
		return
	}
	sub.remote = remoteConn
	sub.connMu.Unlock()
	defer remoteConn.Close()

	idleDur := time.Duration(s.cfg.ConnIdleSec) * time.Second
	if idleDur < 15*time.Second {
		idleDur = 120 * time.Second
	}

	// Upload writer goroutine: drains firstChunk + sub.txCh -> remoteConn
	go func() {
		writeRemote := func(chunk []byte) bool {
			if len(chunk) == 0 {
				return true
			}
			if ul := user.EffectiveLimiter(); ul != nil {
				ul.Wait(len(chunk))
			}
			s.tracker.NodeLimiter.Wait(len(chunk))
			user.AddUpload(int64(len(chunk)))
			_ = remoteConn.SetWriteDeadline(time.Now().Add(idleDur))
			_, werr := remoteConn.Write(chunk)
			return werr == nil
		}
		if len(firstChunk) > 0 && !writeRemote(firstChunk) {
			_ = remoteConn.Close()
			return
		}
		for chunk := range sub.txCh {
			if user.IsDisabled() || sub.aborted.Load() || !writeRemote(chunk) {
				_ = remoteConn.Close()
				return
			}
		}
		if cw, ok := remoteConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	// Download reader loop: remoteConn -> Mux.Cool Keep+Data frames (max 16 KiB per frame)
	const maxMuxChunk = 16384
	rbp := bufpool.Get(8 + maxMuxChunk)
	fbuf := *rbp
	defer bufpool.Put(rbp)

	for {
		if user.IsDisabled() || sub.aborted.Load() {
			return
		}
		_ = remoteConn.SetReadDeadline(time.Now().Add(idleDur))
		n, rerr := remoteConn.Read(fbuf[8 : 8+maxMuxChunk])
		if n > 0 {
			if ul := user.EffectiveLimiter(); ul != nil {
				ul.Wait(n)
			}
			s.tracker.NodeLimiter.Wait(n)
			user.AddDownload(int64(n))

			frame := encodeMuxTCPReplyData(fbuf, sid, fbuf[8:8+n])
			if writeFrame(frame) != nil {
				return
			}
		}
		if rerr != nil {
			isErr := rerr != io.EOF && !sub.aborted.Load()
			_ = writeFrame(encodeMuxTCPEndFrame(sid, isErr))
			return
		}
	}
}
