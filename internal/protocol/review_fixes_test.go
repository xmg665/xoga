package protocol

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/dns"
	"github.com/xmg665/xoga/internal/panel"
	"github.com/xmg665/xoga/internal/stats"
)

type eofFinalReader struct {
	data []byte
}

func (r *eofFinalReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func TestReadFullActiveAndVMessFinalChunkOnNWithEOF(t *testing.T) {
	// 1. readFullActive must return nil (not io.EOF) when reader delivers final bytes with io.EOF.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	var lastActive atomic.Int64
	lastActive.Store(time.Now().UnixNano())

	var out [7]byte
	if err := readFullActive(c1, &eofFinalReader{data: []byte("ABCDEFG")}, out[:], time.Second, &lastActive, nil); err != nil {
		t.Fatalf("readFullActive dropped final bytes returned with io.EOF: %v", err)
	}
	if string(out[:]) != "ABCDEFG" {
		t.Fatalf("readFullActive unexpected bytes %q", out[:])
	}

	// 2. vmessStreamConn.Read must NOT drop final chunk when underlying reader returns (remaining, io.EOF).
	var reqKey, reqIV [16]byte
	_, _ = rand.Read(reqKey[:])
	_, _ = rand.Read(reqIV[:])

	aead, err := makeVMessBodyAEAD(0x03, reqKey[:])
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("vmess-final-chunk-with-eof")
	var nonce [12]byte
	copy(nonce[2:12], reqIV[2:12])
	sealed := aead.Seal(nil, nonce[:], msg, nil)
	var wire bytes.Buffer
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(sealed)))
	wire.Write(lb[:])
	wire.Write(sealed)

	vc, err := newVMessStreamConn(c1, &eofFinalReader{data: wire.Bytes()}, reqKey, reqIV, 0x01, 0x01, 0x03, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer vc.releaseReadBuf()

	dst := make([]byte, 64)
	n, err := vc.Read(dst)
	if err != nil || string(dst[:n]) != string(msg) {
		t.Fatalf("vmessStreamConn dropped final chunk on (n, io.EOF): got n=%d %q err=%v", n, dst[:n], err)
	}
}

func TestUDPRouteKeyDistinguishesSOCKS5Credentials(t *testing.T) {
	rA := acl.OutboundTarget{
		Action: acl.ActionProxy,
		Outbounds: []acl.OutboundNode{
			{Type: "socks5", Server: "proxy.example.com", Port: 1080, Username: "user-us", Password: "p1"},
		},
	}
	rB := acl.OutboundTarget{
		Action: acl.ActionProxy,
		Outbounds: []acl.OutboundNode{
			{Type: "socks5", Server: "proxy.example.com", Port: 1080, Username: "user-jp", Password: "p2"},
		},
	}
	if udpRouteKey(rA, false) == udpRouteKey(rB, false) {
		t.Fatal("udpRouteKey conflated two SOCKS5 outbounds sharing host:port with different credentials")
	}
}

func TestC2LegacyRingChurnHashCollisionClockJumpAndResetRace(t *testing.T) {
	// 1. Forced 64-bit hash collision in legacyRing.index + overflow + eviction
	var ring legacyRing
	u1 := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	u2 := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	now := time.Now().Unix()

	ring.addUUID(u1)
	ring.addUUID(u2)
	ring.advance(now)

	var st [8]byte
	binary.BigEndian.PutUint64(st[:], uint64(now))
	auth1 := hmacMD5Stamp(u1, st)
	auth2 := hmacMD5Stamp(u2, st)
	k1 := binary.LittleEndian.Uint64(auth1[:8])

	// Inject u2's slot under u1's 64-bit key to exercise overflow chain lookup & deletion
	ring.mu.Lock()
	u2Idx := ring.uuidToIdx[u2]
	tsOff := int32(now - ring.baseTS)
	ring.insertEntryLocked(k1, legacySlotVal{uuidIdx: u2Idx, tsOff: tsOff})
	if len(ring.overflow[k1]) == 0 {
		ring.mu.Unlock()
		t.Fatal("expected collision entry to land in overflow map")
	}
	ring.mu.Unlock()

	cfg := config.Default()
	tr := stats.NewTracker(cfg)
	u1Str := fmt.Sprintf("%x-%x-%x-%x-%x", u1[0:4], u1[4:6], u1[6:8], u1[8:10], u1[10:16])
	u2Str := fmt.Sprintf("%x-%x-%x-%x-%x", u2[0:4], u2[4:6], u2[6:8], u2[8:10], u2[10:16])
	users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 1, UUIDOrPass: u1Str, RemainBytes: -1},
		{ID: 2, UUIDOrPass: u2Str, RemainBytes: -1},
	})
	idx := BuildUserIndexForProtocol("vmess", users, 0)

	if e, _, ok := ring.lookup(idx, auth1); !ok || e.User.ID != 1 {
		t.Fatalf("expected u1 match with overflow present, got ok=%v", ok)
	}
	if e, _, ok := ring.lookup(idx, auth2); !ok || e.User.ID != 2 {
		t.Fatalf("expected u2 match, got ok=%v", ok)
	}

	// Clock jump forward > 200s triggers full rebuild and clean eviction of old window
	ring.advance(now + 200)
	if _, _, ok := ring.lookup(idx, auth1); ok {
		t.Fatal("stale timestamp should have been evicted after +200s clock jump")
	}
	var st2 [8]byte
	binary.BigEndian.PutUint64(st2[:], uint64(now+200))
	if e, _, ok := ring.lookup(idx, hmacMD5Stamp(u2, st2)); !ok || e.User.ID != 2 {
		t.Fatal("expected u2 match at new timestamp after +200s clock jump")
	}

	// 2. diffIndexUUIDs must NOT wipe added UUIDs when VMessByUUID is nil
	idxNoMap := &UserIndex{VMessUsers: idx.VMessUsers}
	oldSet := make(map[[16]byte]struct{})
	added, removed := diffIndexUUIDs(oldSet, idxNoMap)
	if len(added) != 2 || len(removed) != 0 || len(oldSet) != 2 {
		t.Fatalf("diffIndexUUIDs with nil VMessByUUID failed: added=%d removed=%d oldSet=%d", len(added), len(removed), len(oldSet))
	}

	// 3. Concurrent rapid churn + ticks + reset race under -race
	var mgr sharedLegacyManager
	var stopChs []chan struct{}
	_ = stopChs
	var wg sync.WaitGroup
	var curIdxA, curIdxB atomic.Pointer[UserIndex]
	curIdxA.Store(idx)
	curIdxB.Store(idx)

	idA := mgr.register(curIdxA.Load)
	idB := mgr.register(curIdxB.Load)

	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			var b [16]byte
			_, _ = rand.Read(b[:])
			s := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
			trLocal := stats.NewTracker(cfg)
			us, _, _, _ := trLocal.ReconcileUsers([]stats.SyncUserSpec{
				{ID: 1, UUIDOrPass: u1Str, RemainBytes: -1},
				{ID: 100 + i, UUIDOrPass: s, RemainBytes: -1},
			})
			ni := BuildUserIndexForProtocol("vmess", us, 0)
			curIdxA.Store(ni)
			mgr.syncNode(idA, ni)
		}
	}()
	go func() {
		defer wg.Done()
		base := time.Now().Unix()
		for i := 1; i <= 25; i++ {
			mgr.ring.advance(base + int64(i))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 60; i++ {
			_, _, _ = mgr.ring.lookup(curIdxB.Load(), auth1)
		}
	}()
	wg.Wait()

	// Unregister all nodes while concurrently racing advanceIfOpen against closed stopCh
	mgr.mu.Lock()
	ch := mgr.stopCh
	mgr.mu.Unlock()
	mgr.unregister(idA)
	mgr.unregister(idB)
	// Calling advanceIfOpen with the closed stopCh MUST NOT resurrect the reset ring!
	mgr.ring.advanceIfOpen(time.Now().Unix()+5, ch)
	mgr.ring.mu.RLock()
	hasWin := mgr.ring.hasWindow
	mgr.ring.mu.RUnlock()
	if hasWin {
		t.Fatal("advanceIfOpen resurrected reset legacyRing after unregister closed stopCh")
	}
}

func TestH3UnidirectionalIdleAnyTLSVLESSMuxAndMuxCoolTCP(t *testing.T) {
	// 1. AnyTLS: unidirectional download > 2.5x idleDur + partial 7-byte header straddling read timeout
	t.Run("AnyTLS_UnidirectionalDownloadAndPartialHeader", func(t *testing.T) {
		// Unidirectional download source: streams 10 chunks over 400ms (> 2.5x 150ms idle)
		srcLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer srcLn.Close()
		srcPort := uint16(srcLn.Addr().(*net.TCPAddr).Port)
		go func() {
			c, err := srcLn.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			for i := 0; i < 10; i++ {
				_, _ = c.Write([]byte("DOWNCHUNK!"))
				time.Sleep(42 * time.Millisecond)
			}
		}()

		anyPort := freeLocalPort(t, "tcp")
		cfg := config.Default()
		cfg.ListenIP = "127.0.0.1"
		cfg.ListenPort = anyPort
		cfg.CertMode = "self"
		tr := stats.NewTracker(cfg)
		pass := "anytls-h3-unidir-pass"
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 21, UUIDOrPass: pass, RemainBytes: -1}})
		spec := &panel.NodeSpec{
			Protocol:   "anytls",
			ListenIP:   "127.0.0.1",
			ServerPort: anyPort,
			Network:    "tcp",
			TLSMode:    1,
			ServerName: "localhost",
		}
		srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("anytls", users, 0), acl.NewEngine(false, "", "", "", nil))
		if err != nil {
			t.Fatal(err)
		}
		srv.testIdleOverride = 150 * time.Millisecond
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		c, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(anyPort)), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))

		hash := sha256.Sum256([]byte(pass))
		var initBuf bytes.Buffer
		initBuf.Write(hash[:])
		initBuf.Write([]byte{0, 0})
		writeAnyFrame := func(w *bytes.Buffer, cmd byte, sid uint32, data []byte) {
			var fh [7]byte
			fh[0] = cmd
			binary.BigEndian.PutUint32(fh[1:5], sid)
			binary.BigEndian.PutUint16(fh[5:7], uint16(len(data)))
			w.Write(fh[:])
			w.Write(data)
		}
		writeAnyFrame(&initBuf, anytlsCmdSettings, 0, []byte("v=2\n"))
		writeAnyFrame(&initBuf, anytlsCmdSYN, 1, nil)
		var addr bytes.Buffer
		addr.Write([]byte{0x01, 127, 0, 0, 1})
		_ = binary.Write(&addr, binary.BigEndian, srcPort)
		writeAnyFrame(&initBuf, anytlsCmdPSH, 1, addr.Bytes())
		if _, err := c.Write(initBuf.Bytes()); err != nil {
			t.Fatal(err)
		}

		// Also drip the first 3 bytes of a HeartRequest header at t=100ms, pause 200ms (>150ms idle!)
		// while download is actively flowing, then send the remaining 4 bytes to prove readFullActive
		// preserves partial header bytes without frame desync!
		go func() {
			var heart [7]byte
			heart[0] = anytlsCmdHeartRequest
			binary.BigEndian.PutUint32(heart[1:5], 77)
			time.Sleep(80 * time.Millisecond)
			_, _ = c.Write(heart[:3])
			time.Sleep(210 * time.Millisecond)
			_, _ = c.Write(heart[3:])
		}()

		var totalDown bytes.Buffer
		gotHeartResp := false
		for totalDown.Len() < 100 || !gotHeartResp {
			var fh [7]byte
			if _, err := io.ReadFull(c, fh[:]); err != nil {
				t.Fatalf("AnyTLS unidirectional read failed after %d bytes (heart=%v): %v", totalDown.Len(), gotHeartResp, err)
			}
			dlen := int(binary.BigEndian.Uint16(fh[5:7]))
			body := make([]byte, dlen)
			if dlen > 0 {
				if _, err := io.ReadFull(c, body); err != nil {
					t.Fatal(err)
				}
			}
			if fh[0] == anytlsCmdPSH && binary.BigEndian.Uint32(fh[1:5]) == 1 {
				totalDown.Write(body)
			} else if fh[0] == anytlsCmdHeartResponse && binary.BigEndian.Uint32(fh[1:5]) == 77 {
				gotHeartResp = true
			}
		}
		if totalDown.String() != strings.Repeat("DOWNCHUNK!", 10) {
			t.Fatalf("unexpected AnyTLS download payload: %q", totalDown.String())
		}
	})

	// 2. VLESS-Mux + Mux.Cool TCP: unidirectional upload > 2.5x idleDur + unidirectional download > 2.5x idleDur
	t.Run("VLESSMux_MuxCoolTCP_UnidirectionalUploadAndDownload", func(t *testing.T) {
		// Target server: reads 10 upload chunks over ~400ms (>2.5x 150ms idle), then streams 10 download chunks over ~400ms
		echoLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer echoLn.Close()
		echoPort := uint16(echoLn.Addr().(*net.TCPAddr).Port)
		go func() {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			got := make([]byte, 80)
			if _, err := io.ReadFull(c, got); err != nil {
				return
			}
			if string(got) != strings.Repeat("UPCHUNK!", 10) {
				return
			}
			for i := 0; i < 10; i++ {
				_, _ = c.Write([]byte("DNCHUNK!"))
				time.Sleep(42 * time.Millisecond)
			}
		}()

		vlessPort := freeLocalPort(t, "tcp")
		cfg := config.Default()
		cfg.ListenIP = "127.0.0.1"
		cfg.ListenPort = vlessPort
		tr := stats.NewTracker(cfg)
		uuidStr := "b831381d-6324-4d53-ad4f-8cda48b30811"
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 22, UUIDOrPass: uuidStr, RemainBytes: -1}})
		spec := &panel.NodeSpec{
			Protocol:   "vless",
			ListenIP:   "127.0.0.1",
			ServerPort: vlessPort,
			Network:    "tcp",
			TLSMode:    0,
		}
		srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("vless", users, 0), acl.NewEngine(false, "", "", "", nil))
		if err != nil {
			t.Fatal(err)
		}
		srv.testIdleOverride = 150 * time.Millisecond
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(vlessPort)), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))

		// VLESS v0 Mux (cmd=0x03) request header (NOTE: vlessRespConn lazily prepends [0x00, 0x00]
		// on the first server write, so send Mux frames before reading the VLESS response header!)
		var hdr bytes.Buffer
		hdr.WriteByte(0x00)
		hdr.Write(users[0].UUIDBytes[:])
		hdr.WriteByte(0x00) // addon len 0
		hdr.WriteByte(0x03) // cmd=Mux
		if _, err := c.Write(hdr.Bytes()); err != nil {
			t.Fatal(err)
		}

		// Send Mux.Cool SessionStatusNew (0x01) TCP (0x01) -> 127.0.0.1:echoPort with first upload chunk
		var openFrame bytes.Buffer
		var meta bytes.Buffer
		_ = binary.Write(&meta, binary.BigEndian, uint16(1)) // sid=1
		meta.WriteByte(0x01)                                 // New
		meta.WriteByte(0x01)                                 // OptionData
		meta.WriteByte(0x01)                                 // NetType TCP
		_ = binary.Write(&meta, binary.BigEndian, echoPort)
		meta.WriteByte(0x01) // IPv4
		meta.Write([]byte{127, 0, 0, 1})
		_ = binary.Write(&openFrame, binary.BigEndian, uint16(meta.Len()))
		openFrame.Write(meta.Bytes())
		_ = binary.Write(&openFrame, binary.BigEndian, uint16(8))
		openFrame.WriteString("UPCHUNK!")
		if _, err := c.Write(openFrame.Bytes()); err != nil {
			t.Fatal(err)
		}

		// Stream remaining 9 upload chunks every 42ms (~380ms total > 2.5x 150ms idle) with ZERO download bytes!
		for i := 1; i < 10; i++ {
			time.Sleep(42 * time.Millisecond)
			var f bytes.Buffer
			_ = binary.Write(&f, binary.BigEndian, uint16(4)) // metaLen=4
			_ = binary.Write(&f, binary.BigEndian, uint16(1)) // sid=1
			f.WriteByte(0x02)                                 // Keep
			f.WriteByte(0x01)                                 // OptionData
			_ = binary.Write(&f, binary.BigEndian, uint16(8))
			f.WriteString("UPCHUNK!")
			if _, err := c.Write(f.Bytes()); err != nil {
				t.Fatalf("mux upload step %d failed: %v", i, err)
			}
		}

		// Read 2-byte VLESS response header prepended before the first server Mux reply frame
		var vresp [2]byte
		if _, err := io.ReadFull(c, vresp[:]); err != nil {
			t.Fatalf("read VLESS resp header: %v", err)
		}

		// Now send ZERO uplink bytes for ~450ms while server streams 10 download chunks over >2.5x 150ms idle!
		var down bytes.Buffer
		for down.Len() < 80 {
			var ml [2]byte
			if _, err := io.ReadFull(c, ml[:]); err != nil {
				t.Fatalf("mux download killed after %d bytes: %v", down.Len(), err)
			}
			mb := make([]byte, binary.BigEndian.Uint16(ml[:]))
			if _, err := io.ReadFull(c, mb); err != nil {
				t.Fatal(err)
			}
			opt := mb[3]
			if (opt & 0x01) != 0 {
				var dl [2]byte
				if _, err := io.ReadFull(c, dl[:]); err != nil {
					t.Fatal(err)
				}
				pay := make([]byte, binary.BigEndian.Uint16(dl[:]))
				if _, err := io.ReadFull(c, pay); err != nil {
					t.Fatal(err)
				}
				down.Write(pay)
			}
		}
		if down.String() != strings.Repeat("DNCHUNK!", 10) {
			t.Fatalf("unexpected mux download payload: %q", down.String())
		}
	})
}

// startMockSOCKS5UDPServer starts a real SOCKS5 server supporting username/password auth and
// UDP ASSOCIATE with optional artificial delay to test non-blocking slow dials under -race.
func startMockSOCKS5UDPServer(t *testing.T, wantUser, wantPass string, dialDelay time.Duration, tag string) (int, *atomic.Int32, func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var udpRelayHits atomic.Int32
	var wg sync.WaitGroup
	var mu sync.Mutex
	var closers []io.Closer

	track := func(c io.Closer) {
		mu.Lock()
		closers = append(closers, c)
		mu.Unlock()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			track(c)
			go func(conn net.Conn) {
				defer conn.Close()
				if dialDelay > 0 {
					time.Sleep(dialDelay)
				}
				var gh [2]byte
				if _, err := io.ReadFull(conn, gh[:]); err != nil || gh[0] != 0x05 {
					return
				}
				methods := make([]byte, gh[1])
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				if wantUser != "" {
					_, _ = conn.Write([]byte{0x05, 0x02})
					var ah [2]byte
					if _, err := io.ReadFull(conn, ah[:]); err != nil {
						return
					}
					ub := make([]byte, ah[1])
					if _, err := io.ReadFull(conn, ub); err != nil {
						return
					}
					var pl [1]byte
					if _, err := io.ReadFull(conn, pl[:]); err != nil {
						return
					}
					pb := make([]byte, pl[0])
					if _, err := io.ReadFull(conn, pb); err != nil {
						return
					}
					if string(ub) != wantUser || string(pb) != wantPass {
						_, _ = conn.Write([]byte{0x01, 0x01})
						return
					}
					_, _ = conn.Write([]byte{0x01, 0x00})
				} else {
					_, _ = conn.Write([]byte{0x05, 0x00})
				}

				var req [10]byte
				if _, err := io.ReadFull(conn, req[:]); err != nil || req[1] != 0x03 {
					return
				}
				upc, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					return
				}
				track(upc)
				defer upc.Close()
				uport := upc.LocalAddr().(*net.UDPAddr).Port
				resp := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(uport >> 8), byte(uport)}
				if _, err := conn.Write(resp); err != nil {
					return
				}

				// Relay UDP packets: unwrap SOCKS5 header, forward to real target, reply tagged!
				go func() {
					buf := make([]byte, 4096)
					for {
						n, cliAddr, rerr := upc.ReadFrom(buf)
						if rerr != nil {
							return
						}
						if n < 10 {
							continue
						}
						pos := 4
						var dstIP net.IP
						switch buf[3] {
						case 0x01:
							dstIP = net.IP(append([]byte(nil), buf[pos:pos+4]...))
							pos += 4
						case 0x04:
							dstIP = net.IP(append([]byte(nil), buf[pos:pos+16]...))
							pos += 16
						default:
							continue
						}
						dstPort := binary.BigEndian.Uint16(buf[pos : pos+2])
						pos += 2
						payload := buf[pos:n]
						udpRelayHits.Add(1)

						// Reply immediately through SOCKS5 encapsulation with tag prefix so caller proves SOCKS5 path!
						var reply bytes.Buffer
						reply.Write([]byte{0x00, 0x00, 0x00})
						if ip4 := dstIP.To4(); ip4 != nil {
							reply.WriteByte(0x01)
							reply.Write(ip4)
						} else {
							reply.WriteByte(0x04)
							reply.Write(dstIP.To16())
						}
						_ = binary.Write(&reply, binary.BigEndian, dstPort)
						reply.WriteString(tag)
						reply.Write(payload)
						_, _ = upc.WriteTo(reply.Bytes(), cliAddr)
					}
				}()

				var one [1]byte
				_, _ = conn.Read(one[:])
			}(c)
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port, &udpRelayHits, func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range closers {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	}
}

func startUDPEchoTag(t *testing.T, network, bindAddr, prefix string) (uint16, func()) {
	t.Helper()
	pc, err := net.ListenPacket(network, bindAddr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte(prefix), buf[:n]...), addr)
		}
	}()
	return uint16(pc.LocalAddr().(*net.UDPAddr).Port), func() { _ = pc.Close() }
}

func TestH5N3M4ConcurrentMultiRouteAndIPv6UDPSessions(t *testing.T) {
	// Start IPv4 direct UDP echo, IPv6 [::1] direct UDP echo, and a slow (60ms) SOCKS5 UDP ASSOCIATE proxy!
	v4Port, stopV4 := startUDPEchoTag(t, "udp4", "127.0.0.1:0", "DIR4:")
	defer stopV4()
	v6Port, stopV6 := startUDPEchoTag(t, "udp6", "[::1]:0", "DIR6:")
	defer stopV6()
	socksPort, socksHits, stopSocks := startMockSOCKS5UDPServer(t, "s5u", "s5p", 60*time.Millisecond, "S5:")
	defer stopSocks()

	// Local UDP DNS mapping:
	//   "v4.direct.local" -> 127.0.0.1
	//   "v6.direct.local" -> ::1
	//   "via.socks.local" -> 127.0.0.1
	dnsPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsPC.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := dnsPC.ReadFrom(buf)
			if err != nil || n < 18 {
				return
			}
			qtype := binary.BigEndian.Uint16(buf[n-4 : n-2])
			// Decode first label to decide response
			l0 := int(buf[12])
			lbl := ""
			if 13+l0 <= n {
				lbl = strings.ToLower(string(buf[13 : 13+l0]))
			}
			resp := make([]byte, 0, n+32)
			resp = append(resp, buf[0], buf[1], 0x81, 0x80, 0x00, 0x01)
			hasAns := false
			var rdata []byte
			if lbl == "v6" && qtype == 28 {
				hasAns = true
				rdata = net.ParseIP("::1").To16()
			} else if lbl != "v6" && qtype == 1 {
				hasAns = true
				rdata = []byte{127, 0, 0, 1}
			}
			if hasAns {
				resp = append(resp, 0x00, 0x01)
			} else {
				resp = append(resp, 0x00, 0x00)
			}
			resp = append(resp, 0x00, 0x00, 0x00, 0x00)
			resp = append(resp, buf[12:n]...)
			if hasAns {
				resp = append(resp, 0xC0, 0x0C)
				var tail [10]byte
				binary.BigEndian.PutUint16(tail[0:2], qtype)
				binary.BigEndian.PutUint16(tail[2:4], 1)
				binary.BigEndian.PutUint32(tail[4:8], 60)
				binary.BigEndian.PutUint16(tail[8:10], uint16(len(rdata)))
				resp = append(resp, tail[:]...)
				resp = append(resp, rdata...)
			}
			_, _ = dnsPC.WriteTo(resp, addr)
		}
	}()
	dnsRes := dns.NewResolver("", "", []string{dnsPC.LocalAddr().String()}, "ipv4_first")

	// routes.toml routing `via.socks.local` through SOCKS5 UDP ASSOCIATE!
	routesFile := filepath.Join(t.TempDir(), "routes.toml")
	routesTOML := fmt.Sprintf(`
enable = true
[[outbounds]]
name = "s5out"
type = "socks5"
server = "127.0.0.1"
port = %d
username = "s5u"
password = "s5p"

[[routes]]
name = "to-socks"
rules = ["full:via.socks.local"]
outbound_tag = "s5out"
`, socksPort)
	if err := os.WriteFile(routesFile, []byte(routesTOML), 0644); err != nil {
		t.Fatal(err)
	}
	aclEng := acl.NewEngine(false, "", "", routesFile, nil)

	// 1. Trojan UDP: single session switching between IPv4 direct, IPv6 direct, and SOCKS5 route, plus M4 downlink-exit close!
	t.Run("TrojanUDP_MultiRouteIPv6AndM4Close", func(t *testing.T) {
		port := freeLocalPort(t, "tcp")
		cfg := config.Default()
		cfg.ListenIP = "127.0.0.1"
		cfg.ListenPort = port
		cfg.ForceCloseSSL = true
		tr := stats.NewTracker(cfg)
		pass := "trojan-multi-udp-pass"
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 31, UUIDOrPass: pass, RemainBytes: -1}})
		spec := &panel.NodeSpec{Protocol: "trojan", ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp", TLSMode: 0}
		srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("trojan", users, 0), aclEng, dnsRes)
		if err != nil {
			t.Fatal(err)
		}
		srv.testIdleOverride = 220 * time.Millisecond
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))

		sum := sha256.Sum224([]byte(pass))
		var hdr bytes.Buffer
		hdr.WriteString(hex.EncodeToString(sum[:]))
		hdr.WriteString("\r\n")
		hdr.WriteByte(0x03) // UDP Associate
		hdr.Write([]byte{0x01, 127, 0, 0, 1})
		_ = binary.Write(&hdr, binary.BigEndian, v4Port)
		hdr.WriteString("\r\n")
		if _, err := c.Write(hdr.Bytes()); err != nil {
			t.Fatal(err)
		}

		writeTrojanPkt := func(atyp byte, addr []byte, p uint16, pay string) {
			var b bytes.Buffer
			b.WriteByte(atyp)
			if atyp == 0x03 {
				b.WriteByte(byte(len(addr)))
			}
			b.Write(addr)
			_ = binary.Write(&b, binary.BigEndian, p)
			_ = binary.Write(&b, binary.BigEndian, uint16(len(pay)))
			b.WriteString("\r\n")
			b.WriteString(pay)
			if _, err := c.Write(b.Bytes()); err != nil {
				t.Fatal(err)
			}
		}
		readTrojanPkt := func() string {
			host, _, err := parseSOCKS5Addr(c)
			if err != nil {
				t.Fatalf("read Trojan UDP addr: %v", err)
			}
			var lc [4]byte
			if _, err := io.ReadFull(c, lc[:]); err != nil {
				t.Fatalf("read Trojan UDP len: %v", err)
			}
			pay := make([]byte, binary.BigEndian.Uint16(lc[0:2]))
			if _, err := io.ReadFull(c, pay); err != nil {
				t.Fatal(err)
			}
			_ = host
			return string(pay)
		}

		// Packet 1: Direct IPv4
		writeTrojanPkt(0x01, []byte{127, 0, 0, 1}, v4Port, "p1")
		if got := readTrojanPkt(); got != "DIR4:p1" {
			t.Fatalf("expected DIR4:p1, got %q", got)
		}
		// Packet 2 (SAME session!): Direct IPv6 [::1]
		writeTrojanPkt(0x04, net.ParseIP("::1").To16(), v6Port, "p2")
		if got := readTrojanPkt(); got != "DIR6:p2" {
			t.Fatalf("expected DIR6:p2 on IPv6 switch in same Trojan UDP session, got %q", got)
		}
		// Packet 3 (SAME session!): Domain routed to SOCKS5 UDP ASSOCIATE!
		writeTrojanPkt(0x03, []byte("via.socks.local"), v4Port, "p3")
		if got := readTrojanPkt(); got != "S5:p3" {
			t.Fatalf("expected S5:p3 on SOCKS5 route switch in same Trojan UDP session, got %q", got)
		}

		// M4: Stop sending; once all UDP sockets idle out (~220ms), downlink exit MUST close client TCP stream!
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var one [1]byte
		if _, err := c.Read(one[:]); err == nil {
			t.Fatal("expected Trojan UDP client stream to be closed on M4 downlink idle exit")
		}
	})

	// 2. VLESS XUDP: same sid switching between IPv4 direct, IPv6 direct, and SOCKS5 route!
	t.Run("VLESSXUDP_MultiRouteAndIPv6", func(t *testing.T) {
		port := freeLocalPort(t, "tcp")
		cfg := config.Default()
		cfg.ListenIP = "127.0.0.1"
		cfg.ListenPort = port
		tr := stats.NewTracker(cfg)
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 32, UUIDOrPass: "75eae340-a037-4cc2-b64c-ae5dc26cc897", RemainBytes: -1}})
		spec := &panel.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp"}
		srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("vless", users, 0), aclEng, dnsRes)
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))

		var hdr bytes.Buffer
		hdr.WriteByte(0x00)
		hdr.Write(users[0].UUIDBytes[:])
		hdr.Write([]byte{0x00, 0x03}) // Mux
		_, _ = c.Write(hdr.Bytes())

		readVResp := false
		sendXUDP := func(sid uint16, atyp byte, addr []byte, p uint16, pay string) {
			var meta bytes.Buffer
			_ = binary.Write(&meta, binary.BigEndian, sid)
			meta.Write([]byte{0x02, 0x01, 0x02}) // Keep, Data, UDP
			_ = binary.Write(&meta, binary.BigEndian, p)
			meta.WriteByte(atyp)
			if atyp == 0x02 {
				meta.WriteByte(byte(len(addr)))
			}
			meta.Write(addr)
			var frame bytes.Buffer
			_ = binary.Write(&frame, binary.BigEndian, uint16(meta.Len()))
			frame.Write(meta.Bytes())
			_ = binary.Write(&frame, binary.BigEndian, uint16(len(pay)))
			frame.WriteString(pay)
			if _, err := c.Write(frame.Bytes()); err != nil {
				t.Fatal(err)
			}
		}
		recvXUDP := func() string {
			if !readVResp {
				var vresp [2]byte
				if _, err := io.ReadFull(c, vresp[:]); err != nil {
					t.Fatalf("read VLESS resp header: %v", err)
				}
				readVResp = true
			}
			var ml [2]byte
			if _, err := io.ReadFull(c, ml[:]); err != nil {
				t.Fatalf("read XUDP reply metaLen: %v", err)
			}
			mb := make([]byte, binary.BigEndian.Uint16(ml[:]))
			if _, err := io.ReadFull(c, mb); err != nil {
				t.Fatal(err)
			}
			var dl [2]byte
			if _, err := io.ReadFull(c, dl[:]); err != nil {
				t.Fatal(err)
			}
			pay := make([]byte, binary.BigEndian.Uint16(dl[:]))
			if _, err := io.ReadFull(c, pay); err != nil {
				t.Fatal(err)
			}
			return string(pay)
		}

		sendXUDP(9, 0x01, []byte{127, 0, 0, 1}, v4Port, "x1")
		if got := recvXUDP(); got != "DIR4:x1" {
			t.Fatalf("expected DIR4:x1, got %q", got)
		}
		sendXUDP(9, 0x03, net.ParseIP("::1").To16(), v6Port, "x2")
		if got := recvXUDP(); got != "DIR6:x2" {
			t.Fatalf("expected DIR6:x2, got %q", got)
		}
		sendXUDP(9, 0x02, []byte("via.socks.local"), v4Port, "x3")
		if got := recvXUDP(); got != "S5:x3" {
			t.Fatalf("expected S5:x3, got %q", got)
		}
	})

	// 3. AnyTLS UoT v2 (non-connect): same stream switching IPv4 direct, IPv6 direct, and SOCKS5 route + M4 close!
	t.Run("AnyTLS_UoT_MultiRouteIPv6AndM4Close", func(t *testing.T) {
		port := freeLocalPort(t, "tcp")
		cfg := config.Default()
		cfg.ListenIP = "127.0.0.1"
		cfg.ListenPort = port
		cfg.CertMode = "self"
		tr := stats.NewTracker(cfg)
		pass := "anytls-uot-multi-pass"
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 33, UUIDOrPass: pass, RemainBytes: -1}})
		spec := &panel.NodeSpec{Protocol: "anytls", ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp", TLSMode: 1, ServerName: "localhost"}
		srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("anytls", users, 0), aclEng, dnsRes)
		if err != nil {
			t.Fatal(err)
		}
		srv.testIdleOverride = 220 * time.Millisecond
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		c, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))

		sendAny := func(cmd byte, sid uint32, body []byte) {
			var fh [7]byte
			fh[0] = cmd
			binary.BigEndian.PutUint32(fh[1:5], sid)
			binary.BigEndian.PutUint16(fh[5:7], uint16(len(body)))
			_, _ = c.Write(append(fh[:], body...))
		}
		hash := sha256.Sum256([]byte(pass))
		_, _ = c.Write(append(hash[:], 0, 0))
		sendAny(anytlsCmdSettings, 0, []byte("v=2\n"))
		sendAny(anytlsCmdSYN, 1, nil)
		// Open UoT v2 stream: SOCKS5 addr = domain "sp.v2.udp-over-tcp.arpa":0, then isConnect=0 + SOCKS5 addr 0.0.0.0:0
		var uotInit bytes.Buffer
		uotInit.WriteByte(0x03)
		uotInit.WriteByte(byte(len(uotMagicV2)))
		uotInit.WriteString(uotMagicV2)
		uotInit.Write([]byte{0, 0})
		uotInit.WriteByte(0x00) // isConnect=false
		uotInit.Write([]byte{0x01, 0, 0, 0, 0, 0, 0})
		sendAny(anytlsCmdPSH, 1, uotInit.Bytes())

		readUoTReply := func() string {
			for {
				var fh [7]byte
				if _, err := io.ReadFull(c, fh[:]); err != nil {
					t.Fatalf("read AnyTLS UoT reply: %v", err)
				}
				body := make([]byte, binary.BigEndian.Uint16(fh[5:7]))
				if len(body) > 0 {
					_, _ = io.ReadFull(c, body)
				}
				if fh[0] == anytlsCmdPSH && binary.BigEndian.Uint32(fh[1:5]) == 1 {
					r := bytes.NewReader(body)
					_, _, err := readUoTAddr(r)
					if err != nil {
						t.Fatalf("parse UoT reply addr: %v", err)
					}
					var l2 [2]byte
					_, _ = io.ReadFull(r, l2[:])
					pay := make([]byte, binary.BigEndian.Uint16(l2[:]))
					_, _ = io.ReadFull(r, pay)
					return string(pay)
				}
			}
		}

		sendUoTPkt := func(af byte, addr []byte, p uint16, pay string) {
			var b bytes.Buffer
			b.WriteByte(af)
			if af == 0x02 {
				b.WriteByte(byte(len(addr)))
			}
			b.Write(addr)
			_ = binary.Write(&b, binary.BigEndian, p)
			_ = binary.Write(&b, binary.BigEndian, uint16(len(pay)))
			b.WriteString(pay)
			sendAny(anytlsCmdPSH, 1, b.Bytes())
		}

		sendUoTPkt(0x00, []byte{127, 0, 0, 1}, v4Port, "u1")
		if got := readUoTReply(); got != "DIR4:u1" {
			t.Fatalf("expected DIR4:u1, got %q", got)
		}
		sendUoTPkt(0x01, net.ParseIP("::1").To16(), v6Port, "u2")
		if got := readUoTReply(); got != "DIR6:u2" {
			t.Fatalf("expected DIR6:u2, got %q", got)
		}
		sendUoTPkt(0x02, []byte("via.socks.local"), v4Port, "u3")
		if got := readUoTReply(); got != "S5:u3" {
			t.Fatalf("expected S5:u3, got %q", got)
		}

		// M4: Stop sending; UoT downlink idle exit must emit cmdFIN for stream 1!
		gotFIN := false
		for !gotFIN {
			var fh [7]byte
			if _, err := io.ReadFull(c, fh[:]); err != nil {
				break
			}
			if dlen := int(binary.BigEndian.Uint16(fh[5:7])); dlen > 0 {
				_, _ = io.CopyN(io.Discard, c, int64(dlen))
			}
			if fh[0] == anytlsCmdFIN && binary.BigEndian.Uint32(fh[1:5]) == 1 {
				gotFIN = true
			}
		}
		if !gotFIN {
			t.Fatal("expected AnyTLS cmdFIN when UoT downlink exited on idle (M4)")
		}
	})

	// 4. Shadowsocks UDP: concurrent multi-route + IPv6 switching under -race (verifies lock release during slow SOCKS5 dial!)
	t.Run("ShadowsocksUDP_ConcurrentMultiRouteAndIPv6", func(t *testing.T) {
		port := freeLocalPort(t, "udp")
		cfg := config.Default()
		cfg.ListenIP = "127.0.0.1"
		cfg.ListenPort = port
		tr := stats.NewTracker(cfg)
		pass := "ss-multi-udp-pass"
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 34, UUIDOrPass: pass, RemainBytes: -1}})
		spec := &panel.NodeSpec{Protocol: "shadowsocks", ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp", Cipher: "aes-128-gcm"}
		srv, err := NewServer(cfg, spec, tr, BuildUserIndexForCipher("shadowsocks", "aes-128-gcm", users), aclEng, dnsRes)
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		cliPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer cliPC.Close()
		srvAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
		cs := srv.ssSpec
		mk := deriveSSKeyExact(pass, cs.keySize, false)

		sendSSUDP := func(atyp byte, addr []byte, p uint16, pay string) {
			var plain bytes.Buffer
			plain.WriteByte(atyp)
			if atyp == 0x03 {
				plain.WriteByte(byte(len(addr)))
			}
			plain.Write(addr)
			_ = binary.Write(&plain, binary.BigEndian, p)
			plain.WriteString(pay)

			salt := make([]byte, cs.saltSize)
			_, _ = rand.Read(salt)
			var sub [32]byte
			deriveSSSubkey(cs, mk, salt, sub[:cs.keySize])
			aead, _ := cs.makeAEAD(sub[:cs.keySize])
			var zn [12]byte
			pkt := append(append([]byte(nil), salt...), aead.Seal(nil, zn[:], plain.Bytes(), nil)...)
			_, _ = cliPC.WriteTo(pkt, srvAddr)
		}

		// Fire SOCKS5 (60ms slow dial), IPv4 direct, AND IPv6 direct concurrently from the SAME client!
		sendSSUDP(0x03, []byte("via.socks.local"), v4Port, "ss-s5")
		sendSSUDP(0x01, []byte{127, 0, 0, 1}, v4Port, "ss-v4")
		sendSSUDP(0x04, net.ParseIP("::1").To16(), v6Port, "ss-v6")

		got := make(map[string]bool)
		buf := make([]byte, 4096)
		_ = cliPC.SetReadDeadline(time.Now().Add(3 * time.Second))
		for len(got) < 3 {
			n, _, err := cliPC.ReadFrom(buf)
			if err != nil {
				t.Fatalf("SS UDP missing replies (got=%v): %v", got, err)
			}
			salt := buf[:cs.saltSize]
			var sub [32]byte
			deriveSSSubkey(cs, mk, salt, sub[:cs.keySize])
			aead, _ := cs.makeAEAD(sub[:cs.keySize])
			var zn [12]byte
			plain, err := aead.Open(nil, zn[:], buf[cs.saltSize:n], nil)
			if err != nil {
				t.Fatal(err)
			}
			r := bytes.NewReader(plain)
			_, _, err = parseSOCKS5Addr(r)
			if err != nil {
				t.Fatal(err)
			}
			rest, _ := io.ReadAll(r)
			got[string(rest)] = true
		}
		for _, want := range []string{"DIR4:ss-v4", "DIR6:ss-v6", "S5:ss-s5"} {
			if !got[want] {
				t.Fatalf("missing expected SS UDP reply %q; got=%v", want, got)
			}
		}
	})

	if socksHits.Load() < 4 {
		t.Fatalf("expected SOCKS5 UDP ASSOCIATE to be hit by all 4 protocols, got %d hits", socksHits.Load())
	}
}

func TestN1N2M5Hysteria2ReauthNon0RTTAndLiteralAfterDomain(t *testing.T) {
	echoTCP, echoUDP := startEchoTCPAndUDP(t)
	hy2Port := freeLocalPort(t, "udp")
	dnsAddr, _, closeDNS := startLocalUDPDNSForLoopback(t)
	defer closeDNS()

	cfg := config.Default()
	cfg.ListenIP = "127.0.0.1"
	cfg.ListenPort = hy2Port
	cfg.CertMode = "self"
	tr := stats.NewTracker(cfg)
	users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 41, UUIDOrPass: "hy2-user-a", RemainBytes: -1},
		{ID: 42, UUIDOrPass: "hy2-user-b", RemainBytes: -1},
	})
	spec := &panel.NodeSpec{
		Protocol:   "hysteria2",
		ListenIP:   "127.0.0.1",
		ServerPort: hy2Port,
		Network:    "quic",
		TLSMode:    1,
		ServerName: "localhost",
	}
	res := dns.NewResolver("", "", []string{dnsAddr}, "ipv4_only")
	srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("hysteria2", users, 0), acl.NewEngine(false, "", "", "", nil), res)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// Dial QUIC + authenticate as User A
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qconn, err := quic.DialAddr(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(hy2Port)), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer qconn.CloseWithError(0, "")

	h3tr := &http3.Transport{}
	cc := h3tr.NewClientConn(qconn)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
	req.Host = "hysteria"
	req.Header.Set("Hysteria-Auth", "hy2-user-a")
	resp, err := cc.RoundTrip(req)
	if err != nil || resp.StatusCode != hy2StatusAuthOK {
		t.Fatalf("Hy2 auth failed: resp=%v err=%v", resp, err)
	}
	_ = resp.Body.Close()

	// N2: Strict non-0-RTT client: send TCPRequest ONLY, wait for TCPResponse (0x00), THEN send payload!
	st, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var tcpReq bytes.Buffer
	tcpReq.Write(quicvarint.Append(nil, hy2FrameTCPRequest))
	targetAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(echoTCP)))
	tcpReq.Write(quicvarint.Append(nil, uint64(len(targetAddr))))
	tcpReq.WriteString(targetAddr)
	tcpReq.Write(quicvarint.Append(nil, 0))
	if _, err := st.Write(tcpReq.Bytes()); err != nil {
		t.Fatal(err)
	}
	// Do NOT send any payload yet — wait for server's TCPResponse first!
	var statusBuf [1]byte
	if _, err := io.ReadFull(st, statusBuf[:]); err != nil || statusBuf[0] != 0x00 {
		t.Fatalf("non-0-RTT Hy2 TCPResponse failed: status=%v err=%v", statusBuf[0], err)
	}
	vr := quicvarint.NewReader(st)
	msgLen, _ := quicvarint.Read(vr)
	if msgLen > 0 {
		_, _ = io.CopyN(io.Discard, st, int64(msgLen))
	}
	padLen, _ := quicvarint.Read(vr)
	if padLen > 0 {
		_, _ = io.CopyN(io.Discard, st, int64(padLen))
	}
	// Now send payload after receiving OK!
	if _, err := st.Write([]byte("non-0rtt-ok")); err != nil {
		t.Fatal(err)
	}
	gotEcho := make([]byte, len("non-0rtt-ok"))
	if _, err := io.ReadFull(st, gotEcho); err != nil || string(gotEcho) != "non-0rtt-ok" {
		t.Fatalf("non-0-RTT Hy2 echo failed: got %q err=%v", gotEcho, err)
	}
	_ = st.Close()

	// M5: Domain UDP packet -> reply uses domain; then literal IP UDP packet on SAME session -> reply MUST use literal IP!
	domTarget := net.JoinHostPort("echo.hy2.local", strconv.Itoa(int(echoUDP)))
	litTarget := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(echoUDP)))
	if err := qconn.SendDatagram(encodeHy2UDPMessage(99, 1, 0, 1, domTarget, []byte("dom"))); err != nil {
		t.Fatal(err)
	}
	dg1, err := qconn.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, rAddr1, rPay1, err := parseHy2UDPMessage(dg1)
	if err != nil || rAddr1 != domTarget || string(rPay1) != "dom" {
		t.Fatalf("expected domain reply %q, got addr=%q pay=%q err=%v", domTarget, rAddr1, rPay1, err)
	}
	if err := qconn.SendDatagram(encodeHy2UDPMessage(99, 2, 0, 1, litTarget, []byte("lit"))); err != nil {
		t.Fatal(err)
	}
	dg2, err := qconn.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, rAddr2, rPay2, err := parseHy2UDPMessage(dg2)
	if err != nil || rAddr2 != litTarget || string(rPay2) != "lit" {
		t.Fatalf("expected literal IP reply %q after domain traffic on same session, got addr=%q pay=%q err=%v", litTarget, rAddr2, rPay2, err)
	}

	// N1: Direct hy2ConnState re-auth edge cases on an open QUIC connection:
	// (a) Currently authed with a user that becomes disabled (pre-close race window) ->
	//     failed re-auth MUST leave authed==false AND user==nil!
	// (b) Subsequent valid re-auth as User B MUST restore authed==true AND user==UserB!
	qconn2, err := quic.DialAddr(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(hy2Port)), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer qconn2.CloseWithError(0, "")

	stObj := &hy2ConnState{
		srv:      srv,
		qconn:    qconn2,
		clientIP: netip.MustParseAddr("127.0.0.1"),
	}
	// Avoid spawning serveDatagrams on client-side qconn2 during ServeHTTP state verification
	stObj.udpOnce.Do(func() {})

	doAuth := func(cred string) int {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "https://hysteria/auth", nil)
		r.Host = "hysteria"
		r.Header.Set("Hysteria-Auth", cred)
		stObj.ServeHTTP(rr, r)
		return rr.Code
	}
	// Simulate an already-authed connection whose user just became disabled before close fires
	staleUser := stats.NewUserEntry(99, "stale-user", 0, 0, 0, false)
	staleUser.DisableAndKick()
	stObj.user.Store(staleUser)
	stObj.authed.Store(true)

	if code := doAuth("wrong-password"); code != http.StatusNotFound {
		t.Fatalf("expected 404 on failed re-auth, got %d", code)
	}
	if stObj.authed.Load() || stObj.user.Load() != nil {
		t.Fatalf("N1 invariant violated after failed re-auth: authed=%v userNil=%v", stObj.authed.Load(), stObj.user.Load() == nil)
	}
	// Now re-authenticate as valid User B on the same live connection
	if code := doAuth("hy2-user-b"); code != hy2StatusAuthOK || !stObj.authed.Load() || stObj.user.Load() != users[1] {
		t.Fatalf("re-auth as User B failed: code=%d authed=%v matchedB=%v", code, stObj.authed.Load(), stObj.user.Load() == users[1])
	}
	// Cleanly release User B's mux session
	if u := stObj.user.Swap(nil); u != nil {
		stObj.authed.Store(false)
		u.ReleaseMuxSession(stObj.sessConnID)
	}
}
