package relay

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/limiter"
	"github.com/xmg665/xoga/internal/stats"
)

type nonTCPWrapper struct {
	net.Conn
}

func TestPipeBidirectionalZeroBufferIdleAndBurst(t *testing.T) {
	// Echo backend server (raw TCP)
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()

	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				// Simulate idle pause before first burst so epoll EAGAIN release path is exercised
				time.Sleep(25 * time.Millisecond)
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	user := stats.NewUserEntry(101, "b831381d-6324-4d53-ad4f-8cda48b30811", 0, 0, 0, false)
	nodeLim := limiter.NewBucketMbps(0)

	go func() {
		for {
			cli, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				rem, err := net.Dial("tcp", echoLn.Addr().String())
				if err != nil {
					return
				}
				defer rem.Close()
				// Wrap client side so `enableZeroCopy=false` / non-splice user-space `tryCopyFromRawTCP` is exercised!
				PipeBidirectional(&nonTCPWrapper{Conn: c}, rem, nil, user, nodeLim, 2*time.Second, false)
			}(cli)
		}
	}()

	conn, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := make([]byte, 96*1024)
	_, _ = rand.Read(payload)

	errCh := make(chan error, 1)
	go func() {
		_, werr := conn.Write(payload)
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		errCh <- werr
	}()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}
	if werr := <-errCh; werr != nil {
		t.Fatalf("write payload: %v", werr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed payload mismatch: got %d bytes, want %d bytes", len(got), len(payload))
	}
}

func TestDisableAndKickSeversStalledRemoteImmediately(t *testing.T) {
	// Stalled remote server that never sends FIN or data
	stallLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stallLn.Close()
	go func() {
		c, err := stallLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(10 * time.Second)
	}()

	cliSrv, cliPeer := net.Pipe()
	defer cliPeer.Close()

	rem, err := net.Dial("tcp", stallLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rem.Close()

	user := stats.NewUserEntry(202, "b831381d-6324-4d53-ad4f-8cda48b30811", 0, 0, 0, false)
	_, err = user.AcquireSession(ExtractClientIP(rem.RemoteAddr()), 60, nil, cliSrv)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		PipeBidirectional(cliSrv, rem, nil, user, limiter.NewBucketMbps(0), 30*time.Second, false)
	}()

	time.Sleep(40 * time.Millisecond)
	user.DisableAndKick()

	select {
	case <-done:
	case <-time.After(400 * time.Millisecond):
		t.Fatal("PipeBidirectional lingered on stalled remoteConn after DisableAndKick()")
	}
}
