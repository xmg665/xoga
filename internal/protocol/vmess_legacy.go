package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// Legacy authentication is limited to explicitly configured users. The ±120-second
// window matches AEAD and covers legacy clients that randomize timestamps plus clock drift.
// M4 fix: cap alterID iteration count at 16 to limit CPU cost from probe traffic.
// When vmess_auth_mode=auto already checked primary UUIDs (n=0) in the shared O(1) ring,
// skip already-indexed timestamps (and short-circuit entirely when no user has alterID > 0)
// so unmatched probes never waste hundreds of HMAC-MD5s per connection.
func (s *Server) readLegacyVMessHeader(idx *UserIndex, reader io.Reader, authID [16]byte) (*VMessUserEntry, []byte, error) {
	now := time.Now().Unix()
	autoActive := s.cfg.VMessAuthMode != "aead"
	if autoActive {
		if ws, we, ok := s.legacy.syncedWindowBounds(idx); ok && ws <= now-legacyAuthWindow && we >= now+legacyAuthWindow {
			hasAlterID := false
			for _, cnt := range s.cfg.VMessLegacyUsers {
				if cnt > 0 {
					hasAlterID = true
					break
				}
			}
			if !hasAlterID {
				return nil, nil, nil
			}
		}
	}
	for i := range idx.VMessUsers {
		entry := &idx.VMessUsers[i]
		count, enabled := s.cfg.VMessLegacyUsers[entry.User.ID]
		if !enabled || entry.User.IsDisabled() {
			continue
		}
		if count > 16 {
			count = 16
		}
		var uWS, uWE int64
		var uCovered bool
		if autoActive {
			uWS, uWE, uCovered = s.legacy.windowBoundsForUUID(idx, entry.User.UUIDBytes)
		}
		id := entry.User.UUIDBytes
		for n := 0; n <= count; n++ {
			if !(n == 0 && uCovered && uWS <= now-legacyAuthWindow && uWE >= now+legacyAuthWindow) {
				var stamp [8]byte
				for ts := now - legacyAuthWindow; ts <= now+legacyAuthWindow; ts++ {
					if n == 0 && uCovered && ts >= uWS && ts <= uWE {
						continue
					}
					binary.BigEndian.PutUint64(stamp[:], uint64(ts))
					tag := hmacMD5Stamp(id, stamp)
					if hmac.Equal(authID[:], tag[:]) {
						header, err := decodeLegacyVMessHeader(reader, entry.CmdKey, stamp)
						return entry, header, err
					}
				}
			}
			if n < count {
				id = nextVMessAlterID(id)
			}
		}
	}
	return nil, nil, nil
}

func nextVMessAlterID(id [16]byte) [16]byte {
	digest := md5.New()
	_, _ = digest.Write(id[:])
	_, _ = digest.Write([]byte("16167dc8-16b6-4e6d-b8bb-65dd68113a81"))
	for {
		var next [16]byte
		digest.Sum(next[:0])
		if next != id {
			return next
		}
		_, _ = digest.Write([]byte("533eff8a-4113-4b10-b5ce-0f5d76b98cd2"))
	}
}

func decodeLegacyVMessHeader(reader io.Reader, key [16]byte, stamp [8]byte) ([]byte, error) {
	var repeated [32]byte
	for i := 0; i < len(repeated); i += len(stamp) {
		copy(repeated[i:], stamp[:])
	}
	iv := md5.Sum(repeated[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	stream := &cipher.StreamReader{S: cipher.NewCFBDecrypter(block, iv[:]), R: reader}
	var header [38 + 2 + 2 + 255 + 15 + 4]byte
	if _, err := io.ReadFull(stream, header[:38]); err != nil {
		return nil, err
	}

	end := 38
	if header[37] == 1 || header[37] == 2 {
		if _, err := io.ReadFull(stream, header[end:end+3]); err != nil {
			return nil, err
		}
		end += 3
		switch header[40] {
		case 1:
			end += 4
		case 2:
			if _, err := io.ReadFull(stream, header[end:end+1]); err != nil {
				return nil, err
			}
			end += 1 + int(header[end])
		case 3:
			end += 16
		default:
			return nil, fmt.Errorf("invalid legacy atyp=0x%02x ver=0x%02x cmd=0x%02x", header[40], header[0], header[37])
		}
	}
	total := end + int(header[35]>>4) + 4
	readFrom := 38
	if header[37] == 1 || header[37] == 2 {
		readFrom = 41
		if header[40] == 2 {
			readFrom++
		}
	}
	if _, err := io.ReadFull(stream, header[readFrom:total]); err != nil {
		return nil, err
	}
	return header[:total], nil
}
