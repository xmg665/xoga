package stats

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/config"
)

func TestQuotaUnpushedReconcileAndUnlimitedRace(t *testing.T) {
	cfg := config.Default()
	tr := NewTracker(cfg)

	entries, added, _, _ := tr.ReconcileUsers([]SyncUserSpec{
		{ID: 1, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811", RemainBytes: 2048},
	})
	if added != 1 || len(entries) != 1 {
		t.Fatalf("expected 1 added user")
	}
	u := entries[0]

	// Consume all 2048 bytes locally (before PushTraffic runs)
	u.AddDownload(2048)
	if !u.IsDisabled() {
		t.Fatalf("expected user to be disabled immediately upon hitting 2048B quota")
	}

	// Simulate panel pull firing BEFORE PushTraffic: panel still reports RemainBytes=2048!
	entries, _, _, _ = tr.ReconcileUsers([]SyncUserSpec{
		{ID: 1, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811", RemainBytes: 2048},
	})
	if !entries[0].IsDisabled() {
		t.Fatalf("over-quota user with 2048B unpushed traffic must NOT be re-enabled by stale panel RemainBytes=2048")
	}

	// Simulate user topping up to 10240B on panel (even before PushTraffic): 10240 - 2048 = 8192 > 0 -> re-enabled!
	entries, _, updated, _ := tr.ReconcileUsers([]SyncUserSpec{
		{ID: 1, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811", RemainBytes: 10240},
	})
	if entries[0].IsDisabled() || updated == 0 {
		t.Fatalf("expected user to be re-enabled after top-up (disabled=%v updated=%d)", entries[0].IsDisabled(), updated)
	}

	// Concurrent race check: switching to unlimited (-1) while traffic is flowing must never falsely kick user
	u2 := NewUserEntry(2, "c942492e-7435-4e64-be50-9deb59c41922", 0, 0, 0, false)
	u2.SetRemainingQuota(-1)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				u2.AddUpload(500)
				u2.AddDownload(500)
			}
		}()
	}
	wg.Wait()
	if u2.IsDisabled() {
		t.Fatalf("unlimited user must never be disabled by AddUpload/AddDownload")
	}
}

func TestMuxSubStreamTCPLimit(t *testing.T) {
	u := NewUserEntry(10, "secret", 0, 2, 2, false)
	ip := netip.MustParseAddr("1.2.3.4")

	// Outer mux session must NOT consume activeTCP slot
	cid, err := u.AcquireMuxSession(ip, 60, nil, nil)
	if err != nil {
		t.Fatalf("AcquireMuxSession failed: %v", err)
	}
	defer u.ReleaseMuxSession(cid)

	if err := u.AcquireSubStream(); err != nil {
		t.Fatalf("substream 1 failed: %v", err)
	}
	if err := u.AcquireSubStream(); err != nil {
		t.Fatalf("substream 2 failed: %v", err)
	}
	if err := u.AcquireSubStream(); err != ErrTCPLimit {
		t.Fatalf("expected 3rd substream to hit ErrTCPLimit, got %v", err)
	}
	u.ReleaseSubStream()
	if err := u.AcquireSubStream(); err != nil {
		t.Fatalf("substream after release failed: %v", err)
	}
	u.ReleaseSubStream()
	u.ReleaseSubStream()
}

func TestRedisIPLimiterEvictsRejectedIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Minimal in-memory mock Redis ZSET server speaking RESP2
	go func() {
		var mu sync.Mutex
		zsets := make(map[string]map[string]int64)

		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "*") {
						continue
					}
					argc, _ := strconv.Atoi(line[1:])
					args := make([]string, 0, argc)
					for i := 0; i < argc; i++ {
						bl, err := br.ReadString('\n')
						if err != nil {
							return
						}
						n, _ := strconv.Atoi(strings.TrimSpace(bl[1:]))
						buf := make([]byte, n+2)
						if _, err := io.ReadFull(br, buf); err != nil {
							return
						}
						args = append(args, string(buf[:n]))
					}
					if len(args) == 0 {
						continue
					}
					mu.Lock()
					switch strings.ToUpper(args[0]) {
					case "ZREMRANGEBYSCORE":
						_, _ = conn.Write([]byte(":0\r\n"))
					case "ZADD":
						key, scoreStr, member := args[1], args[2], args[3]
						sc, _ := strconv.ParseInt(scoreStr, 10, 64)
						if zsets[key] == nil {
							zsets[key] = make(map[string]int64)
						}
						_, existed := zsets[key][member]
						zsets[key][member] = sc
						if existed {
							_, _ = conn.Write([]byte(":0\r\n"))
						} else {
							_, _ = conn.Write([]byte(":1\r\n"))
						}
					case "ZCARD":
						key := args[1]
						_, _ = conn.Write([]byte(":" + strconv.Itoa(len(zsets[key])) + "\r\n"))
					case "EXPIRE":
						_, _ = conn.Write([]byte(":1\r\n"))
					case "ZREM":
						key, member := args[1], args[2]
						if zsets[key] != nil {
							delete(zsets[key], member)
						}
						_, _ = conn.Write([]byte(":1\r\n"))
					}
					mu.Unlock()
				}
			}(c)
		}
	}()

	cfg := config.Default()
	cfg.RedisIPLimitEnable = true
	cfg.RedisIPLimitAddr = ln.Addr().String()
	lim := newRedisIPLimiter(cfg)

	if ok, err := lim.CheckAndTouch(88, "1.1.1.1", 2, 60); err != nil || !ok {
		t.Fatalf("IP 1 should pass: ok=%v err=%v", ok, err)
	}
	if ok, err := lim.CheckAndTouch(88, "2.2.2.2", 2, 60); err != nil || !ok {
		t.Fatalf("IP 2 should pass: ok=%v err=%v", ok, err)
	}
	// 3rd IP must be rejected AND removed via ZREM
	if ok, err := lim.CheckAndTouch(88, "3.3.3.3", 2, 60); err != nil || ok {
		t.Fatalf("IP 3 should be rejected: ok=%v err=%v", ok, err)
	}
	// Legitimate IP 1 & IP 2 must STILL be allowed afterwards!
	time.Sleep(5 * time.Millisecond)
	if ok, err := lim.CheckAndTouch(88, "1.1.1.1", 2, 60); err != nil || !ok {
		t.Fatalf("existing valid IP 1 was falsely locked out after IP 3 rejection! ok=%v err=%v", ok, err)
	}
}

func TestCredentialRotationKicksOldSessionsAndPreservesTraffic(t *testing.T) {
	cfg := config.Default()
	tr := NewTracker(cfg)

	entries, _, _, _ := tr.ReconcileUsers([]SyncUserSpec{
		{ID: 7, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811", AltPasswd: "old-pass", DeviceLimit: 1},
	})
	oldU := entries[0]
	c1, c2 := net.Pipe()
	defer c2.Close()
	_, err := oldU.AcquireSession(netip.MustParseAddr("1.1.1.1"), 60, nil, c1)
	if err != nil {
		t.Fatal(err)
	}
	oldU.AddUpload(4096)

	// Rotate password (and drop AltPasswd) -> old socket must be kicked, old password revoked, 4096B preserved!
	entries2, _, updated, _ := tr.ReconcileUsers([]SyncUserSpec{
		{ID: 7, UUIDOrPass: "c942492e-7435-4e64-be50-9deb59c41922", DeviceLimit: 1},
	})
	if updated != 1 || entries2[0] == oldU || entries2[0].Passwd == "old-pass" {
		t.Fatalf("expected fresh UserEntry on credential rotation, updated=%d pass=%q", updated, entries2[0].Passwd)
	}
	_ = c2.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var one [1]byte
	if _, rerr := c2.Read(one[:]); rerr == nil {
		t.Fatal("expected pre-existing session on rotated credentials to be closed immediately")
	}
	deltas := tr.HarvestTraffic(0)
	if len(deltas) != 1 || deltas[0].Upload != 4096 {
		t.Fatalf("expected 4096B unpushed traffic carried over across credential rotation, got %+v", deltas)
	}

	// Verify Xboard integer remote alive count enforcement + clearing when empty
	u := entries2[0]
	tr.ApplyRemoteAliveCounts(map[int]int{7: 1})
	if err := u.AcquireConn(netip.MustParseAddr("9.9.9.9"), 60, nil); err != ErrIPLimit {
		t.Fatalf("expected ErrIPLimit when Xboard remoteCount=1 == DeviceLimit=1, got %v", err)
	}
	tr.ApplyRemoteAliveList(map[int][]string{}) // cluster goes idle -> clears remoteCount!
	if err := u.AcquireConn(netip.MustParseAddr("9.9.9.9"), 60, nil); err != nil {
		t.Fatalf("expected new IP to succeed after empty /alivelist cleared stale remoteCount, got %v", err)
	}
	u.ReleaseConn()
}
