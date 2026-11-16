// Package devd reads the notifications the kernel publishes through devd(8) (the seqpacket socket of devd) and turns
// the few that matter to an operator into JailOps events: a ZFS error, a pool changing state, the link of the uplink going down, a resource limit that was hit by a jail.
//
// The records are text, one per packet: a type character and, for a notification, key=value pairs (devctl(4)):
//
//	!system=ZFS subsystem=ZFS type=ereport.fs.zfs.checksum pool=tank vdev_path=/dev/da0
//
// Nothing here may break the daemon: a missing or unreadable socket is retried slowly, and a record that does not parse
// is dropped.
package devd

import (
	"strings"
	"unicode/utf8"
)

// Limits of what the parser accepts. A record longer than MaxRecord is dropped whole: the kernel's records are short,
// and a long one is not one of the few JailOps wants.
const (
	MaxRecord = 8 << 10
	maxFields = 64
	maxKey    = 64
)

// Record is one notification (type character '!') of devd.
type Record struct {
	Fields map[string]string
}

// Get returns a field, or "" when the record has none.
func (r Record) Get(key string) string { return r.Fields[key] }

// Parse reads one record. It returns false for everything that is not a well formed notification: an attach, a detach,
// a nomatch, an empty or oversized packet, text that is not UTF-8 or has control characters, and a pair without a key.
func Parse(packet []byte) (Record, bool) {
	if len(packet) == 0 || len(packet) > MaxRecord || packet[0] != '!' || !utf8.Valid(packet) {
		return Record{}, false
	}
	s := strings.TrimRight(string(packet[1:]), "\r\n")
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return Record{}, false
		}
	}
	fields := map[string]string{}
	for s = strings.TrimLeft(s, " "); s != ""; s = strings.TrimLeft(s, " ") {
		eq := strings.IndexByte(s, '=')
		if eq < 1 || eq > maxKey {
			return Record{}, false
		}
		key := s[:eq]
		if !validKey(key) {
			return Record{}, false
		}
		val, rest, ok := value(s[eq+1:])
		if !ok || len(fields) >= maxFields {
			return Record{}, false
		}
		if _, dup := fields[key]; !dup {
			fields[key] = val
		}
		s = rest
	}
	if len(fields) == 0 {
		return Record{}, false
	}
	return Record{Fields: fields}, true
}

func validKey(k string) bool {
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' || c == ':') {
			return false
		}
	}
	return true
}

// value reads a plain value (up to the next space) or a quoted one with the escapes of devctl(4): a backslash before a
// backslash or a double quote.
func value(s string) (val, rest string, ok bool) {
	if !strings.HasPrefix(s, `"`) {
		sp := strings.IndexByte(s, ' ')
		if sp < 0 {
			return s, "", true
		}
		return s[:sp], s[sp:], true
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s) && (s[i+1] == '\\' || s[i+1] == '"'):
			b.WriteByte(s[i+1])
			i++
		case c == '"':
			return b.String(), s[i+1:], true
		default:
			b.WriteByte(c)
		}
	}
	return "", "", false // the quote never closed
}
