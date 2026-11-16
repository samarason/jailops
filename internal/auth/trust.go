package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"jailops.net/jailops/sdk/api"
)

// TrustPrefix starts every trust token.
const TrustPrefix = "joc_"

// MaxTrustTTL bounds the lifetime of a trust token.
const MaxTrustTTL = 30 * 24 * time.Hour

// TrustClaims is the content of a trust token. The grant (role, projects) is
// stored on the server under ID, not in the token.
type TrustClaims struct {
	Version int    `json:"v"`
	ID      string `json:"id"`
	// Name is the certificate name the token is bound to.
	Name string `json:"name"`
	// ServerFingerprint is the SHA-256 fingerprint of the server certificate,
	// which the client pins before it sends anything.
	ServerFingerprint string `json:"fp"`
	// Expires is the expiry in unix seconds.
	Expires int64  `json:"exp"`
	Secret  string `json:"sec"`
}

var errTrust = api.Errorf(api.CodeUnauthorized, "invalid trust token")

func trustMAC(key []byte, payload string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("jailops-trust:"))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// NewTrustToken creates a token bound to name, valid for ttl, protected by an
// HMAC under key and carrying the server certificate fingerprint.
func NewTrustToken(key []byte, name, serverFingerprint string, ttl time.Duration, now time.Time) (string, TrustClaims, error) {
	if len(key) < 16 {
		return "", TrustClaims{}, errors.New("auth: trust key too short")
	}
	if !api.IsName(name, api.MaxName) {
		return "", TrustClaims{}, api.Errorf(api.CodeInvalid, "invalid name %q", name).WithHint("use lowercase letters, digits, '-', '_' and '.'")
	}
	fp, err := NormalizeFingerprint(serverFingerprint)
	if err != nil {
		return "", TrustClaims{}, api.Errorf(api.CodeInvalid, "%v", err)
	}
	if ttl <= 0 || ttl > MaxTrustTTL {
		return "", TrustClaims{}, api.Errorf(api.CodeInvalid, "trust token lifetime must be between 1s and %s", MaxTrustTTL)
	}
	var id, sec [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", TrustClaims{}, err
	}
	if _, err := rand.Read(sec[:]); err != nil {
		return "", TrustClaims{}, err
	}
	c := TrustClaims{Version: 1, ID: urlEnc.EncodeToString(id[:]), Name: name, ServerFingerprint: fp,
		Expires: now.Add(ttl).Unix(), Secret: urlEnc.EncodeToString(sec[:])}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", TrustClaims{}, err
	}
	p := urlEnc.EncodeToString(raw)
	return TrustPrefix + p + "." + urlEnc.EncodeToString(trustMAC(key, p)), c, nil
}

func decodeTrust(token string) (TrustClaims, string, []byte, error) {
	var c TrustClaims
	rest, ok := strings.CutPrefix(token, TrustPrefix)
	if !ok {
		return c, "", nil, errTrust
	}
	p, sig, ok := strings.Cut(rest, ".")
	if !ok {
		return c, "", nil, errTrust
	}
	got, err := urlEnc.DecodeString(sig)
	if err != nil {
		return c, "", nil, errTrust
	}
	raw, err := urlEnc.DecodeString(p)
	if err != nil || json.Unmarshal(raw, &c) != nil || c.Version != 1 || c.ID == "" {
		return TrustClaims{}, "", nil, errTrust
	}
	return c, p, got, nil
}

// ParseTrustToken checks the HMAC (constant time) and the structure, without
// the expiry. Every failure is the same unauthorized error.
func ParseTrustToken(key []byte, token string) (TrustClaims, error) {
	c, p, sig, err := decodeTrust(token)
	if err != nil {
		return TrustClaims{}, err
	}
	if !hmac.Equal(sig, trustMAC(key, p)) {
		return TrustClaims{}, errTrust
	}
	return c, nil
}

// VerifyTrustToken is ParseTrustToken plus the expiry and the requirement
// that the token names this server's fingerprint. It does not consume the
// token; the caller does that atomically with the store.
func VerifyTrustToken(key []byte, token, serverFingerprint string, now time.Time) (TrustClaims, error) {
	c, err := ParseTrustToken(key, token)
	if err != nil {
		return TrustClaims{}, err
	}
	fp, ferr := NormalizeFingerprint(serverFingerprint)
	if ferr != nil || fp != c.ServerFingerprint || now.Unix() >= c.Expires {
		return TrustClaims{}, errTrust
	}
	return c, nil
}

// TrustTokenFingerprint reads the server fingerprint from a token without
// verifying it, for clients that do not hold the key and pin the server
// before sending the token.
func TrustTokenFingerprint(token string) (string, error) {
	c, _, _, err := decodeTrust(token)
	if err != nil {
		return "", err
	}
	return NormalizeFingerprint(c.ServerFingerprint)
}
