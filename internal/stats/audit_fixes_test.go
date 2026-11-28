package stats

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/config"
)

func TestN4RedisZRemRetryAndNoFailOpenAndM3PoolConcurrency(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var mu sync.Mutex
	zsets := make(map[string]map[string]int64)
	var dropFirstZRem atomic.Bool
	dropFirstZRem.Store(true)
	var zaddForIP3Count atomic.Int32
	var slowUserID atomic.Int32

	go func() {
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
					cmd := strings.ToUpper(args[0])
					if cmd == "ZADD" && len(args) >= 4 && args[1] == "xoga:ip:"+strconv.Itoa(int(slowUserID.Load())) {
						time.Sleep(250 * time.Millisecond)
					}
					if cmd == "ZREM" && dropFirstZRem.CompareAndSwap(true, false) {
						// Drop TCP connection RIGHT when first ZREM arrives!
						_ = conn.Close()
						return
					}
					mu.Lock()
					switch cmd {
					case "ZREMRANGEBYSCORE":
						_, _ = conn.Write([]byte(":0\r\n"))
					case "ZADD":
						key, scoreStr, member := args[1], args[2], args[3]
						if member == "3.3.3.3" {
							zaddForIP3Count.Add(1)
						}
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

	// Fill user 55 to maxIPs=2
	if ok, err := lim.CheckAndTouch(55, "1.1.1.1", 2, 60); err != nil || !ok {
		t.Fatalf("IP1 failed: ok=%v err=%v", ok, err)
	}
	if ok, err := lim.CheckAndTouch(55, "2.2.2.2", 2, 60); err != nil || !ok {
		t.Fatalf("IP2 failed: ok=%v err=%v", ok, err)
	}
	// IP3 triggers ZREM failure on first conn -> retry must run ONLY ZREM (NOT re-run ZADD!) and reject IP3
	if ok, err := lim.CheckAndTouch(55, "3.3.3.3", 2, 60); err != nil || ok {
		t.Fatalf("IP3 must be rejected even after first ZREM conn drop: ok=%v err=%v", ok, err)
	}
	if got := zaddForIP3Count.Load(); got != 1 {
		t.Fatalf("retry must NOT re-run ZADD for IP3 after ZREM failure; got %d ZADDs", got)
	}
	mu.Lock()
	_, polluted := zsets["xoga:ip:55"]["3.3.3.3"]
	mu.Unlock()
	if polluted {
		t.Fatal("IP3 polluted Redis ZSET after ZREM retry!")
	}

	// M3: Pooled connections must allow fast user 66 to complete while slow user 99 stalls for 250ms
	slowUserID.Store(99)
	doneSlow := make(chan struct{})
	go func() {
		defer close(doneSlow)
		_, _ = lim.CheckAndTouch(99, "9.9.9.9", 2, 60)
	}()
	time.Sleep(25 * time.Millisecond)

	start := time.Now()
	if ok, err := lim.CheckAndTouch(66, "6.6.6.6", 2, 60); err != nil || !ok {
		t.Fatalf("fast user 66 failed: ok=%v err=%v", ok, err)
	}
	if elapsed := time.Since(start); elapsed > 120*time.Millisecond {
		t.Fatalf("fast user 66 was serialized behind slow user 99 (%v > 120ms)", elapsed)
	}
	<-doneSlow
}

func TestM9ReconcileUsersEmptyCredAndDuplicateIDDedup(t *testing.T) {
	cfg := config.Default()
	tr := NewTracker(cfg)

	entries, added, updated, removed := tr.ReconcileUsers([]SyncUserSpec{
		{ID: 0, UUIDOrPass: "valid-but-id-zero"},
		{ID: 1, UUIDOrPass: "", AltPasswd: ""},
		{ID: 2, UUIDOrPass: "   ", AltPasswd: "  "},
		{ID: 10, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"},
		{ID: 10, UUIDOrPass: "75eae340-a037-4cc2-b64c-ae5dc26cc897"}, // duplicate ID 10 in same payload!
	})
	if added != 1 || updated != 0 || removed != 0 || len(entries) != 1 || entries[0].ID != 10 {
		t.Fatalf("expected only deduplicated user 10, got entries=%d added=%d updated=%d removed=%d", len(entries), added, updated, removed)
	}
}
