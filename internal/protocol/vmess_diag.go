package protocol

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"hash/crc32"
	"sync/atomic"
	"time"

	"github.com/xmg665/xoga/internal/logger"
)

// vmessDiagBudget limits the expensive unmatched-AuthID diagnosis to a few runs per second.
var (
	vmessDiagSec   atomic.Int64
	vmessDiagCount atomic.Int32
)

const vmessDiagPerSec = 5

func vmessDiagAllowed() bool {
	now := time.Now().Unix()
	if vmessDiagSec.Load() != now {
		vmessDiagSec.Store(now)
		vmessDiagCount.Store(0)
	}
	return vmessDiagCount.Add(1) <= vmessDiagPerSec
}

// diagnoseUnmatchedVMess explains why an AuthID matched no user. It returns
// "aead_clock_skew user=<id> skew=<sec>", "legacy_md5 user=<id> skew=<sec>",
// "unknown", or "skipped" when the rate limit is exhausted. No credentials are returned.
func diagnoseUnmatchedVMess(idx *UserIndex, authID [16]byte) (string, int, int64) {
	if !logger.Default().Enabled(logger.LevelDebug) || !vmessDiagAllowed() {
		return "skipped", 0, 0
	}
	now := time.Now().Unix()
	var scratch [16]byte
	for i, blk := range idx.VMessBlocks {
		blk.Decrypt(scratch[:], authID[:])
		if crc32.ChecksumIEEE(scratch[:12]) == binary.BigEndian.Uint32(scratch[12:16]) {
			return "aead_clock_skew", idx.VMessUsers[i].User.ID, int64(binary.BigEndian.Uint64(scratch[:8])) - now
		}
	}
	var stamp [8]byte
	var tag [16]byte
	for i := range idx.VMessUsers {
		id := idx.VMessUsers[i].User.UUIDBytes
		mac := hmac.New(md5.New, id[:])
		for ts := now - 120; ts <= now+120; ts++ {
			binary.BigEndian.PutUint64(stamp[:], uint64(ts))
			mac.Reset()
			_, _ = mac.Write(stamp[:])
			if hmac.Equal(authID[:], mac.Sum(tag[:0])) {
				return "legacy_md5", idx.VMessUsers[i].User.ID, ts - now
			}
		}
	}
	return "unknown", 0, 0
}
