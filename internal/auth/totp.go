package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"time"
)

// TOTPConfig selects the RFC 6238 parameters. The zero value means SHA-1,
// 6 digits, 30 seconds: what authenticator apps expect.
type TOTPConfig struct {
	Digits int // 6 to 9
	Period time.Duration
	Hash   func() hash.Hash
}

func (c TOTPConfig) norm() TOTPConfig {
	if c.Digits == 0 {
		c.Digits = 6
	}
	if c.Period == 0 {
		c.Period = 30 * time.Second
	}
	if c.Hash == nil {
		c.Hash = sha1.New
	}
	return c
}

// Hash constructors for TOTPConfig.
var (
	HashSHA1   = sha1.New
	HashSHA256 = sha256.New
	HashSHA512 = sha512.New
)

// hotp is RFC 4226 dynamic truncation.
func hotp(secret []byte, counter uint64, digits int, h func() hash.Hash) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(h, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint64(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, uint64(bin)%mod)
}

// TOTPCode computes the code valid at t.
func TOTPCode(secret []byte, t time.Time, cfg TOTPConfig) string {
	cfg = cfg.norm()
	return hotp(secret, uint64(t.Unix())/uint64(cfg.Period/time.Second), cfg.Digits, cfg.Hash)
}

// TOTPValidate checks code against the steps within skew steps of now. It
// returns the matched time-step counter so the caller can reject replays by
// remembering the highest counter accepted (pass it as lastUsed; counters
// less than or equal to it are refused).
func TOTPValidate(secret []byte, code string, now time.Time, skew int, lastUsed int64, cfg TOTPConfig) (counter int64, ok bool) {
	cfg = cfg.norm()
	if len(code) != cfg.Digits {
		return 0, false
	}
	cur := now.Unix() / int64(cfg.Period/time.Second)
	for d := -skew; d <= skew; d++ {
		c := cur + int64(d)
		if c < 0 || c <= lastUsed {
			continue
		}
		want := hotp(secret, uint64(c), cfg.Digits, cfg.Hash)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			ok = true
			counter = c // keep scanning so timing does not depend on the match position
		}
	}
	return counter, ok
}

// GenerateTOTPSecret returns 20 random bytes (160 bits).
func GenerateTOTPSecret() ([]byte, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("auth: entropy: %w", err)
	}
	return b, nil
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeTOTPSecret renders the secret for manual entry.
func EncodeTOTPSecret(secret []byte) string { return b32.EncodeToString(secret) }

// TOTPProvisioningURI returns the otpauth:// URI shown as a QR code.
func TOTPProvisioningURI(issuer, account string, secret []byte) string {
	q := url.Values{}
	q.Set("secret", EncodeTOTPSecret(secret))
	q.Set("issuer", issuer)
	return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(account) + "?" + q.Encode()
}

// Recovery codes.

// RecoveryCodeBits is the entropy of a recovery code: too many to search, so a copy of the database does not give the
// second factor away.
const RecoveryCodeBits = 128

// GenerateRecoveryCodes returns n codes (formatted xxxxx-xxxxx-xxxxx-xxxxx-xxxxxx, 128 bits each) and their storage
// entries: each with a salt of its own. Show the codes once; store only the entries.
func GenerateRecoveryCodes(n int) (codes, hashes []string, err error) {
	for range n {
		var b [RecoveryCodeBits / 8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, nil, fmt.Errorf("auth: entropy: %w", err)
		}
		s := strings.ToLower(b32.EncodeToString(b[:])) // 128 bits -> 26 chars
		code := s[:5] + "-" + s[5:10] + "-" + s[10:15] + "-" + s[15:20] + "-" + s[20:]
		var salt [16]byte
		if _, err := rand.Read(salt[:]); err != nil {
			return nil, nil, fmt.Errorf("auth: entropy: %w", err)
		}
		codes = append(codes, code)
		hashes = append(hashes, recoveryEntry(salt[:], code))
	}
	return codes, hashes, nil
}

const recoveryPrefix = "v1$"

func normalizeRecovery(code string) string {
	return strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(code))
}

// recoveryEntry is "v1$<salt>$<sha256(salt, code)>", both in hex.
func recoveryEntry(salt []byte, code string) string {
	h := sha256.New()
	h.Write([]byte("jailops-recovery:"))
	h.Write(salt)
	h.Write([]byte(normalizeRecovery(code)))
	return recoveryPrefix + hex.EncodeToString(salt) + "$" + hex.EncodeToString(h.Sum(nil))
}

// MatchRecoveryCode reports whether code is the one stored as entry, comparing in constant time. A code carries 128
// random bits and a salt of its own, so a plain SHA-256 is as good as a slow hash here: there is nothing to search.
func MatchRecoveryCode(code, entry string) bool {
	rest, ok := strings.CutPrefix(entry, recoveryPrefix)
	if !ok {
		return false
	}
	saltHex, _, ok := strings.Cut(rest, "$")
	if !ok {
		return false
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(recoveryEntry(salt, code)), []byte(entry)) == 1
}
