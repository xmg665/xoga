package bufpool

import "sync"

const (
	SmallSize  = 2 * 1024  // 2 KiB: protocol handshakes, SNI/HTTP peeking, DNS packets
	MediumSize = 16 * 1024 // 16 KiB: AEAD encrypted chunks (Shadowsocks/VMess max payload + tag)
	LargeSize  = 32 * 1024 // 32 KiB: TCP stream relay & UDP datagram buffers
	MaxUDPSize = 64 * 1024 // 64 KiB: max UDP datagram buffer
)

var (
	smallPool = sync.Pool{
		New: func() any {
			b := make([]byte, SmallSize)
			return &b
		},
	}
	mediumPool = sync.Pool{
		New: func() any {
			b := make([]byte, MediumSize)
			return &b
		},
	}
	largePool = sync.Pool{
		New: func() any {
			b := make([]byte, LargeSize)
			return &b
		},
	}
	udpPool = sync.Pool{
		New: func() any {
			b := make([]byte, MaxUDPSize)
			return &b
		},
	}
)

// Get returns a pointer to a pooled byte slice of at least size bytes.
// Storing *[]byte in sync.Pool avoids interface header boxing allocations on Put.
func Get(size int) *[]byte {
	switch {
	case size <= SmallSize:
		bp := smallPool.Get().(*[]byte)
		*bp = (*bp)[:size]
		return bp
	case size <= MediumSize:
		bp := mediumPool.Get().(*[]byte)
		*bp = (*bp)[:size]
		return bp
	case size <= LargeSize:
		bp := largePool.Get().(*[]byte)
		*bp = (*bp)[:size]
		return bp
	case size <= MaxUDPSize:
		bp := udpPool.Get().(*[]byte)
		*bp = (*bp)[:size]
		return bp
	default:
		b := make([]byte, size)
		return &b
	}
}

// Put returns a pooled slice pointer back to its matching slab class.
func Put(bp *[]byte) {
	if bp == nil {
		return
	}
	c := cap(*bp)
	switch c {
	case SmallSize:
		*bp = (*bp)[:SmallSize]
		smallPool.Put(bp)
	case MediumSize:
		*bp = (*bp)[:MediumSize]
		mediumPool.Put(bp)
	case LargeSize:
		*bp = (*bp)[:LargeSize]
		largePool.Put(bp)
	case MaxUDPSize:
		*bp = (*bp)[:MaxUDPSize]
		udpPool.Put(bp)
	}
}
