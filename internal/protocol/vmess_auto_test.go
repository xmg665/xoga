package protocol

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/stats"
)

func TestLegacyAuthCacheMatchesAnyUser(t *testing.T) {
	cfg := config.Default()
	cfg.ApplyKV("vmess_auth_mode", "auto")
	if cfg.VMessAuthMode != "auto" {
		t.Fatalf("vmess_auth_mode not parsed: %q", cfg.VMessAuthMode)
	}
	tracker := stats.NewTracker(cfg)
	users, _, _, _ := tracker.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 1, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"},
		{ID: 2, UUIDOrPass: "75eae340-a037-4cc2-b64c-ae5dc26cc897"},
	})
	idx := BuildUserIndexForProtocol("vmess", users, 0)
	var c legacyAuthCache
	now := time.Now().Unix()
	c.refresh(idx, now)

	authFor := func(u *stats.UserEntry, ts int64) [16]byte {
		var stamp [8]byte
		binary.BigEndian.PutUint64(stamp[:], uint64(ts))
		mac := hmac.New(md5.New, u.UUIDBytes[:])
		mac.Write(stamp[:])
		var out [16]byte
		copy(out[:], mac.Sum(nil))
		return out
	}
	for _, u := range users {
		for _, off := range []int64{-legacyAuthWindow, -30, 0, 30, legacyAuthWindow} {
			entry, stamp, ok := c.lookup(authFor(u, now+off))
			if !ok || entry.User.ID != u.ID || int64(binary.BigEndian.Uint64(stamp[:])) != now+off {
				t.Fatalf("user %d offset %d not matched", u.ID, off)
			}
		}
		if _, _, ok := c.lookup(authFor(u, now+legacyAuthWindow+1)); ok {
			t.Fatalf("user %d matched outside window", u.ID)
		}
	}
	// Sliding forward keeps the window centred on the new time.
	c.refresh(idx, now+10)
	if _, _, ok := c.lookup(authFor(users[0], now+10+legacyAuthWindow)); !ok {
		t.Fatal("bucket not added after slide")
	}
	if _, _, ok := c.lookup(authFor(users[0], now-legacyAuthWindow)); ok {
		t.Fatal("stale bucket kept after slide")
	}
}
