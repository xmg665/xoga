package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"hash/fnv"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/panel"
	"github.com/xmg665/xoga/internal/stats"
)

func TestLegacyVMessAuthentication(t *testing.T) {
	echoHost, echoPort, closeEcho := startEchoTCPServer(t)
	defer closeEcho()
	cfg := config.Default()
	cfg.ApplyKV("vmess_legacy_users", "55:1")
	tracker := stats.NewTracker(cfg)
	users, _, _, _ := tracker.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 55, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"},
		{ID: 56, UUIDOrPass: "75eae340-a037-4cc2-b64c-ae5dc26cc897"},
	})
	idx := BuildUserIndexForProtocol("vmess", users, 0)
	port := freeTCPPort(t)
	spec := &panel.NodeSpec{Protocol: "vmess", ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp"}
	server, err := NewServer(cfg, spec, tracker, idx, acl.NewEngine(false, "", "", "", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	for _, tc := range []struct {
		name   string
		userID int
		alter  bool
		accept bool
	}{
		{"primary UUID", 55, false, true},
		{"first AlterID", 55, true, true},
		{"user outside allowlist", 56, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var user *stats.UserEntry
			for _, candidate := range users {
				if candidate.ID == tc.userID {
					user = candidate
				}
			}
			var stamp [8]byte
			binary.BigEndian.PutUint64(stamp[:], uint64(time.Now().Unix()))
			id := user.UUIDBytes
			if tc.alter {
				id = md5.Sum(append(id[:], []byte("16167dc8-16b6-4e6d-b8bb-65dd68113a81")...))
			}
			mac := hmac.New(md5.New, id[:])
			mac.Write(stamp[:])
			request := mac.Sum(nil)
			key := md5.Sum(append(user.UUIDBytes[:], []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")...))
			iv := md5.Sum(bytes.Repeat(stamp[:], 4))
			block, _ := aes.NewCipher(key[:])
			header := make([]byte, 42)
			header[0], header[1], header[17], header[33] = 1, 2, byte(len(tc.name)), 4
			header[35], header[37], header[40], header[41] = 5, 1, 2, byte(len(echoHost))
			binary.BigEndian.PutUint16(header[38:40], echoPort)
			if tc.alter {
				header[35] = 1
			}
			header = append(header, echoHost...)
			sum := fnv.New32a()
			sum.Write(header)
			header = sum.Sum(header)
			requestKey, requestIV := [16]byte(header[17:33]), [16]byte(header[1:17])
			responseKey := md5.Sum(requestKey[:])
			responseIV := md5.Sum(requestIV[:])
			cipher.NewCFBEncrypter(block, iv[:]).XORKeyStream(header, header)
			const body = "legacy VMess echo"
			payload := []byte(body)
			if tc.alter {
				bodyBlock, _ := aes.NewCipher(requestKey[:])
				cipher.NewCFBEncrypter(bodyBlock, requestIV[:]).XORKeyStream(payload, payload)
			}
			request = append(append(request, header...), payload...)
			dial := func() net.Conn {
				t.Helper()
				conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { conn.Close() })
				conn.SetDeadline(time.Now().Add(time.Second))
				if _, err := conn.Write(request); err != nil {
					t.Fatal(err)
				}
				return conn
			}
			expectRejected := func(conn net.Conn) {
				t.Helper()
				var response [1]byte
				if n, err := conn.Read(response[:]); n != 0 || err == nil {
					t.Fatalf("unexpected response: %d bytes, %v", n, err)
				} else if e, ok := err.(net.Error); ok && e.Timeout() {
					t.Fatalf("server stalled: %v", err)
				}
			}
			conn := dial()
			if !tc.accept {
				expectRejected(conn)
				return
			}
			var response [4 + len(body)]byte
			if _, err := io.ReadFull(conn, response[:]); err != nil {
				t.Fatal(err)
			}
			block, _ = aes.NewCipher(responseKey[:])
			responseCipher := cipher.NewCFBDecrypter(block, responseIV[:])
			responseCipher.XORKeyStream(response[:4], response[:4])
			if tc.alter {
				responseCipher.XORKeyStream(response[4:], response[4:])
			}
			if response[0] != 4 || string(response[4:]) != body {
				t.Fatalf("invalid response: %x", response)
			}
			expectRejected(dial())
		})
	}
}
