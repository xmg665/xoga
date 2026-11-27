package protocol

import (
	"net"
	"testing"
	"time"
)

// Regression: abort while enqueue is blocked on a full txCh must not panic
// with "send on closed channel".
func TestMuxSubAbortWhileEnqueueBlocked(t *testing.T) {
	for i := 0; i < 200; i++ {
		sub := newMuxTCPSubSession()
		for j := 0; j < cap(sub.txCh); j++ {
			sub.txCh <- []byte{1}
		}
		done := make(chan bool, 1)
		go func() { done <- sub.enqueue([]byte("x")) }()
		time.Sleep(time.Millisecond)
		sub.abort()
		select {
		case ok := <-done:
			if ok {
				t.Fatal("enqueue reported success after abort")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("enqueue not woken by abort")
		}
	}
}

// Regression: Close must not wait for a reader blocked in readSingleChunk.
func TestVMessStreamCloseUnblocksReader(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	v := &vmessStreamConn{Conn: server, reader: server, rawStream: true}
	readDone := make(chan struct{})
	go func() {
		var b [16]byte
		_, _ = v.Read(b[:])
		close(readDone)
	}()
	time.Sleep(20 * time.Millisecond)
	closed := make(chan struct{})
	go func() { _ = v.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked by pending Read")
	}
	<-readDone
}
