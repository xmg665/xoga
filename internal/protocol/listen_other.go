//go:build !linux

package protocol

import (
	"context"
	"net"
	"time"
)

func listenTCP(ctx context.Context, addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		KeepAlive: 45 * time.Second,
	}
	return lc.Listen(ctx, "tcp", addr)
}
