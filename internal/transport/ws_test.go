package transport

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// Regression: a short read deadline firing mid-WebSocket-frame-header or mid-PING
// must preserve header/control progress and never desync the WebSocket stream.
func TestWSConnMidHeaderTimeoutPreservesStream(t *testing.T) {
	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()

	w := &wsConn{
		Conn:      srvConn,
		rawWriter: srvConn,
		br:        bufio.NewReaderSize(srvConn, 2048),
	}

	// Build a masked binary WS frame: FIN=1 opcode=2, masked=1 len=11, mask=0x11223344
	payload := []byte("hello-ws-ok")
	mask := [4]byte{0x11, 0x22, 0x33, 0x44}
	frame := make([]byte, 2+4+len(payload))
	frame[0] = 0x82
	frame[1] = 0x80 | byte(len(payload))
	copy(frame[2:6], mask[:])
	for i := range payload {
		frame[6+i] = payload[i] ^ mask[i&3]
	}

	// Split right inside the 6-byte WS frame header (send 3 bytes, sleep 100ms, send rest)
	go func() {
		_, _ = cliConn.Write(frame[:3])
		time.Sleep(100 * time.Millisecond)
		_, _ = cliConn.Write(frame[3:])
	}()

	buf := make([]byte, 64)
	_ = w.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	n, err := w.Read(buf)
	var ne net.Error
	if n != 0 || !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("expected timeout mid-WS-header, got n=%d err=%v", n, err)
	}

	_ = w.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = w.Read(buf)
	if err != nil {
		t.Fatalf("resumed WS Read failed: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("WS payload mismatch: got %q want %q", buf[:n], payload)
	}
}
