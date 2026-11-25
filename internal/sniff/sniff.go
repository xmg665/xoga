package sniff

import (
	"bytes"
	"encoding/binary"
	"strings"
)

var (
	btMagic       = []byte("\x13BitTorrent protocol")
	dhtPingMagic  = []byte("d1:ad2:id20:")
	dhtRespMagic  = []byte("d1:rd2:id20:")
	dhtQueryMagic = []byte("d1:yq1:")
	utMetaMagic   = []byte("ut_metadata")
	utPexMagic    = []byte("ut_pex")
	announceMagic = []byte("/announce?info_hash=")
	scrapeMagic   = []byte("/scrape?info_hash=")
)

// Result contains protocol & destination metadata inspected from initial payload bytes.
type Result struct {
	Protocol string // "tls", "http", "bittorrent", ""
	Domain   string
}

// Inspect inspects initial client payload bytes without mutating or copying the slice.
func Inspect(b []byte) Result {
	if len(b) == 0 {
		return Result{}
	}
	if IsBitTorrent(b) {
		return Result{Protocol: "bittorrent"}
	}
	if sni, ok := SniffTLSClientHello(b); ok {
		return Result{Protocol: "tls", Domain: sni}
	}
	if host, ok := SniffHTTPHost(b); ok {
		return Result{Protocol: "http", Domain: host}
	}
	return Result{}
}

// IsBitTorrent performs fast zero-allocation signature checks for BitTorrent TCP, uTP, DHT, and Trackers.
func IsBitTorrent(b []byte) bool {
	if len(b) >= 20 && bytes.Equal(b[:20], btMagic) {
		return true
	}
	if bytes.Contains(b, dhtPingMagic) || bytes.Contains(b, dhtRespMagic) || bytes.Contains(b, dhtQueryMagic) {
		return true
	}
	if bytes.Contains(b, utMetaMagic) || bytes.Contains(b, utPexMagic) {
		return true
	}
	if bytes.Contains(b, announceMagic) || bytes.Contains(b, scrapeMagic) {
		return true
	}
	return false
}

// SniffTLSClientHello extracts the SNI hostname from a TLS ClientHello record.
func SniffTLSClientHello(b []byte) (string, bool) {
	// Record header: ContentType(1)==0x16, Version(2), Length(2)
	if len(b) < 43 || b[0] != 0x16 || b[1] != 0x03 {
		return "", false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	end := 5 + recLen
	if end > len(b) {
		end = len(b)
	}
	p := b[5:end]
	// HandshakeType(1)==0x01 (ClientHello), Length(3), Version(2), Random(32)
	if len(p) < 38 || p[0] != 0x01 {
		return "", false
	}
	pos := 4 + 2 + 32
	if pos >= len(p) {
		return "", false
	}
	// Session ID
	sidLen := int(p[pos])
	pos += 1 + sidLen
	if pos+2 > len(p) {
		return "", false
	}
	// Cipher Suites
	csLen := int(binary.BigEndian.Uint16(p[pos : pos+2]))
	pos += 2 + csLen
	if pos+1 > len(p) {
		return "", false
	}
	// Compression Methods
	compLen := int(p[pos])
	pos += 1 + compLen
	if pos+2 > len(p) {
		return "", false
	}
	// Extensions
	extTotal := int(binary.BigEndian.Uint16(p[pos : pos+2]))
	pos += 2
	extEnd := pos + extTotal
	if extEnd > len(p) {
		extEnd = len(p)
	}

	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(p[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(p[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > extEnd {
			break
		}
		if extType == 0x0000 && extLen >= 5 { // server_name extension
			listLen := int(binary.BigEndian.Uint16(p[pos : pos+2]))
			q := pos + 2
			listEnd := q + listLen
			if listEnd > pos+extLen {
				listEnd = pos + extLen
			}
			for q+3 <= listEnd {
				nameType := p[q]
				nameLen := int(binary.BigEndian.Uint16(p[q+1 : q+3]))
				q += 3
				if q+nameLen > listEnd {
					break
				}
				if nameType == 0x00 && nameLen > 0 {
					host := strings.ToLower(string(p[q : q+nameLen]))
					return host, true
				}
				q += nameLen
			}
		}
		pos += extLen
	}
	return "", false
}

// SniffHTTPHost extracts the Host header from an HTTP/1.x request.
func SniffHTTPHost(b []byte) (string, bool) {
	if len(b) < 16 {
		return "", false
	}
	// Quick HTTP method prefix check
	switch b[0] {
	case 'G', 'P', 'H', 'D', 'O', 'C', 'T':
	default:
		return "", false
	}
	firstLineEnd := bytes.IndexByte(b, '\n')
	if firstLineEnd <= 4 || firstLineEnd > 2048 {
		return "", false
	}
	if !bytes.Contains(b[:firstLineEnd], []byte("HTTP/1.")) {
		return "", false
	}
	rest := b[firstLineEnd+1:]
	for len(rest) > 0 {
		nl := bytes.IndexByte(rest, '\n')
		var line []byte
		if nl >= 0 {
			line = rest[:nl]
			rest = rest[nl+1:]
		} else {
			line = rest
			rest = nil
		}
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			break
		}
		if len(line) >= 5 && (line[0] == 'H' || line[0] == 'h') &&
			(line[1] == 'o' || line[1] == 'O') &&
			(line[2] == 's' || line[2] == 'S') &&
			(line[3] == 't' || line[3] == 'T') && line[4] == ':' {
			val := strings.TrimSpace(string(line[5:]))
			if colon := strings.LastIndexByte(val, ':'); colon > 0 && !strings.Contains(val, "]") {
				val = val[:colon]
			}
			val = strings.ToLower(strings.Trim(val, "[]"))
			if val != "" {
				return val, true
			}
		}
	}
	return "", false
}
