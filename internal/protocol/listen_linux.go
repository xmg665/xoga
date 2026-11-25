//go:build linux

package protocol

import (
	"context"
	"net"
	"syscall"
	"time"
)

const tcpFastOpenLinux = 23 // TCP_FASTOPEN on Linux

func listenTCP(ctx context.Context, addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		KeepAlive: 45 * time.Second,
		Control: func(_, _ string, c syscall.RawConn) error {
			_ = c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				// Enable kernel TCP Fast Open queue (matches `net.ipv4.tcp_fastopen = 3` & HAProxy `tfo`)
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpFastOpenLinux, 256)
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
			})
			return nil
		},
	}
	return lc.Listen(ctx, "tcp", addr)
}
