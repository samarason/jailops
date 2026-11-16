package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"jailops.net/jailops/sdk/api"
)

// PasswordParams are the argon2id cost parameters, stored in each hash.
type PasswordParams struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
	SaltLen   uint32
	KeyLen    uint32
}

// DefaultPasswordParams is the production cost.
var DefaultPasswordParams = PasswordParams{MemoryKiB: 64 * 1024, Time: 3, Threads: 4, SaltLen: 16, KeyLen: 32}

// Limits applied when parsing a stored hash, so that a tampered database row
// cannot make the daemon allocate unbounded memory.
const (
	maxParseMemoryKiB = 1 << 20 // 1 GiB
	maxParseTime      = 32
	maxParseKeyLen    = 128
)

var b64 = base64.RawStdEncoding

// HashPassword returns a PHC string: $argon2id$v=19$m=..,t=..,p=..$salt$hash.
func HashPassword(password string, p PasswordParams) (string, error) {
	if p.MemoryKiB == 0 || p.Time == 0 || p.Threads == 0 || p.SaltLen < 8 || p.KeyLen < 16 {
		return "", fmt.Errorf("auth: invalid argon2id parameters")
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: entropy: %w", err)
	}
	key := derive(func() []byte { return argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, p.KeyLen) })
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

func parseHash(h string) (p PasswordParams, salt, key []byte, err error) {
	bad := fmt.Errorf("auth: malformed password hash")
	parts := strings.Split(h, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, bad
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return p, nil, nil, fmt.Errorf("auth: unsupported argon2 version %q", parts[2])
	}
	var m, t, th uint64
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return p, nil, nil, bad
		}
		n, perr := strconv.ParseUint(v, 10, 32)
		if perr != nil {
			return p, nil, nil, bad
		}
		switch k {
		case "m":
			m = n
		case "t":
			t = n
		case "p":
			th = n
		default:
			return p, nil, nil, bad
		}
	}
	if m == 0 || t == 0 || th == 0 || th > 255 || m > maxParseMemoryKiB || t > maxParseTime {
		return p, nil, nil, bad
	}
	if salt, err = b64.DecodeString(parts[4]); err != nil || len(salt) < 8 {
		return p, nil, nil, bad
	}
	if key, err = b64.DecodeString(parts[5]); err != nil || len(key) < 16 || len(key) > maxParseKeyLen {
		return p, nil, nil, bad
	}
	return PasswordParams{MemoryKiB: uint32(m), Time: uint32(t), Threads: uint8(th), SaltLen: uint32(len(salt)), KeyLen: uint32(len(key))}, salt, key, nil
}

// VerifyPassword checks password against a PHC hash in constant time. A
// malformed hash is an error; a wrong password is (false, nil).
func VerifyPassword(password, hash string) (bool, error) {
	p, salt, key, err := parseHash(hash)
	if err != nil {
		return false, err
	}
	got := derive(func() []byte {
		return argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(key)))
	})
	return subtle.ConstantTimeCompare(got, key) == 1, nil
}

// NeedsRehash reports whether hash was made with weaker parameters than want.
func NeedsRehash(hash string, want PasswordParams) bool {
	p, _, key, err := parseHash(hash)
	if err != nil {
		return true
	}
	return p.MemoryKiB < want.MemoryKiB || p.Time < want.Time || p.Threads != want.Threads || uint32(len(key)) < want.KeyLen
}

// BurnPasswordTime spends one argon2id derivation at the given cost so that
// login timing does not reveal whether a user exists.
func BurnPasswordTime(password string, p PasswordParams) {
	_ = derive(func() []byte { return argon2.IDKey([]byte(password), burnSalt, p.Time, p.MemoryKiB, p.Threads, 32) })
}

var burnSalt = []byte("jailops-burn-salt")

// Password policy.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

var commonPasswords = map[string]bool{
	"password1234": true, "123456789012": true, "qwertyuiopas": true, "iloveyou1234": true,
	"administrator": true, "passwordpassword": true, "letmein12345": true, "changeme1234": true,
	"freebsdfreebsd": true, "jailopsjailops": true, "welcome12345": true, "123456123456": true,
}

// CheckPasswordPolicy enforces length, variety and a few obvious rejections.
// username may be empty.
func CheckPasswordPolicy(password, username string) error {
	n := utf8.RuneCountInString(password)
	switch {
	case !utf8.ValidString(password):
		return api.Errorf(api.CodeInvalid, "password is not valid UTF-8")
	case n < MinPasswordLen:
		return api.Errorf(api.CodeInvalid, "password must have at least %d characters", MinPasswordLen)
	case len(password) > MaxPasswordLen:
		return api.Errorf(api.CodeInvalid, "password must have at most %d bytes", MaxPasswordLen)
	}
	distinct := map[rune]struct{}{}
	for _, r := range password {
		distinct[r] = struct{}{}
	}
	if len(distinct) < 5 {
		return api.Errorf(api.CodeInvalid, "password uses too few distinct characters")
	}
	low := strings.ToLower(password)
	if commonPasswords[low] {
		return api.Errorf(api.CodeInvalid, "password is too common")
	}
	if len(username) >= 3 && strings.Contains(low, strings.ToLower(username)) {
		return api.Errorf(api.CodeInvalid, "password must not contain the user name")
	}
	return nil
}
