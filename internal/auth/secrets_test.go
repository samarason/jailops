package auth

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
)

func TestTokenGenerateVerify(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		s, h, err := GenerateToken()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(s, "jot_") || !TokenWellFormed(s) || len(h) != 32 || seen[s] {
			t.Fatalf("bad token %q", s)
		}
		seen[s] = true
		if !VerifyToken(s, h) {
			t.Fatal("verify failed")
		}
		if VerifyToken(s+"x", h) || VerifyToken("jot_"+s[4:len(s)-1]+"a", h) && s[len(s)-1] != 'a' {
			t.Fatal("wrong token verified")
		}
		if !bytes.Equal(h, HashToken(s)) {
			t.Fatal("hash mismatch")
		}
	}
	if VerifyToken("jot_x", []byte{1, 2}) {
		t.Fatal("short stored hash accepted")
	}
	for _, bad := range []string{"", "jot_", "xyz_" + strings.Repeat("a", 52), "jot_" + strings.Repeat("!", 52), "jot_" + strings.Repeat("a", 51)} {
		if TokenWellFormed(bad) {
			t.Errorf("%q well-formed", bad)
		}
	}
}

func TestCheckTokenUse(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr
	tests := []struct {
		name  string
		exp   time.Time
		allow []string
		from  netip.Addr
		want  api.Code
	}{
		{"no limits", time.Time{}, nil, ip("1.2.3.4"), ""},
		{"not expired", now.Add(time.Second), nil, ip("1.2.3.4"), ""},
		{"expired", now.Add(-time.Second), nil, ip("1.2.3.4"), api.CodeUnauthorized},
		{"expires exactly now", now, nil, ip("1.2.3.4"), api.CodeUnauthorized},
		{"cidr hit", time.Time{}, []string{"10.0.0.0/8"}, ip("10.9.9.9"), ""},
		{"cidr miss", time.Time{}, []string{"10.0.0.0/8"}, ip("11.0.0.1"), api.CodeForbidden},
		{"single ip", time.Time{}, []string{"192.0.2.7"}, ip("192.0.2.7"), ""},
		{"v4-mapped source", time.Time{}, []string{"192.0.2.0/24"}, ip("::ffff:192.0.2.9"), ""},
		{"v6 prefix", time.Time{}, []string{"2001:db8::/32"}, ip("2001:db8::5"), ""},
		{"second entry", time.Time{}, []string{"10.0.0.0/8", "172.16.0.0/12"}, ip("172.20.0.1"), ""},
		{"invalid source", time.Time{}, []string{"10.0.0.0/8"}, netip.Addr{}, api.CodeForbidden},
	}
	for _, tc := range tests {
		err := CheckTokenUse(tc.exp, tc.allow, now, tc.from)
		if tc.want == "" && err != nil || tc.want != "" && !api.IsCode(err, tc.want) {
			t.Errorf("%s: %v want %q", tc.name, err, tc.want)
		}
	}
	if ValidateAllowFrom([]string{"10.0.0.0/8", "::1"}) != nil || ValidateAllowFrom([]string{"nope"}) == nil {
		t.Fatal("ValidateAllowFrom")
	}
}

var fast = PasswordParams{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("correct horse battery", fast)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=64,t=1,p=1$") || strings.Count(h, "$") != 5 {
		t.Fatalf("not PHC: %s", h)
	}
	if ok, err := VerifyPassword("correct horse battery", h); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if ok, err := VerifyPassword("wrong", h); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	h2, _ := HashPassword("correct horse battery", fast)
	if h == h2 {
		t.Fatal("salt reused")
	}
	if NeedsRehash(h, fast) {
		t.Fatal("same params need rehash")
	}
	stronger := fast
	stronger.Time = 2
	if !NeedsRehash(h, stronger) {
		t.Fatal("weaker hash not flagged")
	}
	if !NeedsRehash("garbage", fast) {
		t.Fatal("garbage not flagged")
	}
	if _, err := HashPassword("x", PasswordParams{}); err == nil {
		t.Fatal("zero params accepted")
	}
	// the default cost works too
	dh, err := HashPassword("pw", DefaultPasswordParams)
	if err != nil || !strings.Contains(dh, "m=65536,t=3,p=4") {
		t.Fatalf("%v %s", err, dh)
	}
}

func TestVerifyPasswordMalformed(t *testing.T) {
	good, _ := HashPassword("pw", fast)
	parts := strings.Split(good, "$")
	mk := func(i int, v string) string {
		p := append([]string(nil), parts...)
		p[i] = v
		return strings.Join(p, "$")
	}
	for name, h := range map[string]string{
		"empty":          "",
		"wrong alg":      mk(1, "argon2i"),
		"wrong version":  mk(2, "v=16"),
		"huge memory":    mk(3, "m=4194304,t=1,p=1"),
		"huge time":      mk(3, "m=64,t=9999,p=1"),
		"zero threads":   mk(3, "m=64,t=1,p=0"),
		"unknown param":  mk(3, "m=64,t=1,p=1,x=2"),
		"non numeric":    mk(3, "m=a,t=1,p=1"),
		"bad salt":       mk(4, "!!"),
		"short salt":     mk(4, "AAAA"),
		"bad key":        mk(5, "!!"),
		"short key":      mk(5, "AAAA"),
		"too few fields": strings.Join(parts[:5], "$"),
	} {
		if ok, err := VerifyPassword("pw", h); ok || err == nil {
			t.Errorf("%s: ok=%v err=%v", name, ok, err)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	tests := []struct {
		pw, user string
		ok       bool
	}{
		{"correct horse battery", "alice", true},
		{"short1!", "alice", false},
		{"aaaaaaaaaaaaaaaa", "alice", false},
		{"abababababababab", "alice", false},
		{"Password1234", "alice", false},
		{"my-alice-password-x", "Alice", false},
		{"my-al-password-xyz", "al", true}, // names under 3 chars are not matched
		{strings.Repeat("x1y2z", 60), "bob", false},
		{"pässwörd-länger-ok", "bob", true},
		{"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4", "bob", false},
		{"", "", false},
	}
	for _, tc := range tests {
		err := CheckPasswordPolicy(tc.pw, tc.user)
		if (err == nil) != tc.ok {
			t.Errorf("%q/%q: %v", tc.pw, tc.user, err)
		}
		if err != nil && !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("wrong code %v", err)
		}
	}
	BurnPasswordTime("x", fast) // must not panic
}

func TestTOTPRFC6238Vectors(t *testing.T) {
	secrets := map[string][]byte{
		"sha1":   []byte("12345678901234567890"),
		"sha256": []byte("12345678901234567890123456789012"),
		"sha512": []byte("1234567890123456789012345678901234567890123456789012345678901234"),
	}
	cfgs := map[string]TOTPConfig{
		"sha1":   {Digits: 8, Hash: HashSHA1},
		"sha256": {Digits: 8, Hash: HashSHA256},
		"sha512": {Digits: 8, Hash: HashSHA512},
	}
	vectors := []struct {
		unix                 int64
		sha1, sha256, sha512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}
	for _, v := range vectors {
		at := time.Unix(v.unix, 0)
		for alg, want := range map[string]string{"sha1": v.sha1, "sha256": v.sha256, "sha512": v.sha512} {
			if got := TOTPCode(secrets[alg], at, cfgs[alg]); got != want {
				t.Errorf("t=%d %s: got %s want %s", v.unix, alg, got, want)
			}
		}
	}
}

func TestTOTPValidate(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	code := TOTPCode(secret, now, TOTPConfig{})
	if len(code) != 6 {
		t.Fatal(code)
	}
	c, ok := TOTPValidate(secret, code, now, 1, 0, TOTPConfig{})
	if !ok || c != now.Unix()/30 {
		t.Fatalf("%v %d", ok, c)
	}
	// replay: counter at or below lastUsed is refused
	if _, ok := TOTPValidate(secret, code, now, 1, c, TOTPConfig{}); ok {
		t.Fatal("replay accepted")
	}
	// previous step accepted with skew 1, refused with skew 0
	prev := TOTPCode(secret, now.Add(-30*time.Second), TOTPConfig{})
	if _, ok := TOTPValidate(secret, prev, now, 1, 0, TOTPConfig{}); !ok {
		t.Fatal("skew step refused")
	}
	if _, ok := TOTPValidate(secret, prev, now, 0, 0, TOTPConfig{}); ok {
		t.Fatal("skew 0 accepted previous step")
	}
	// far away step refused
	far := TOTPCode(secret, now.Add(-10*time.Minute), TOTPConfig{})
	if _, ok := TOTPValidate(secret, far, now, 1, 0, TOTPConfig{}); ok {
		t.Fatal("old code accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "000000"} {
		if bad == code {
			continue
		}
		if _, ok := TOTPValidate(secret, bad, now, 1, 0, TOTPConfig{}); ok && bad != prev {
			t.Errorf("%q accepted", bad)
		}
	}
	sec, err := GenerateTOTPSecret()
	if err != nil || len(sec) != 20 {
		t.Fatal(err)
	}
	uri := TOTPProvisioningURI("JailOps", "alice@host", sec)
	if !strings.HasPrefix(uri, "otpauth://totp/JailOps:alice@host?") || !strings.Contains(uri, "secret="+EncodeTOTPSecret(sec)) || !strings.Contains(uri, "issuer=JailOps") {
		t.Fatal(uri)
	}
}

func TestSessionAndCSRF(t *testing.T) {
	id, h, err := NewSessionID()
	if err != nil || len(id) != 43 || !bytes.Equal(h, HashSessionID(id)) {
		t.Fatal(err)
	}
	id2, _, _ := NewSessionID()
	if id == id2 {
		t.Fatal("repeat")
	}
	c1, _ := NewCSRFToken()
	c2, _ := NewCSRFToken()
	if c1 == c2 || !CSRFValid(c1, c1) || CSRFValid(c1, c2) || CSRFValid("", "") || CSRFValid(c1, c1[:10]) {
		t.Fatal("CSRFValid")
	}
	ck := SessionCookie(id, true, 12*time.Hour)
	if ck.Name != "__Host-jailops_session" || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" || ck.MaxAge != 43200 || ck.Domain != "" {
		t.Fatalf("%+v", ck)
	}
	if ck := SessionCookie(id, false, time.Hour); ck.Name != "jailops_session" || ck.Secure {
		t.Fatalf("%+v", ck)
	}
	if ClearSessionCookie(true).MaxAge >= 0 {
		t.Fatal("clear")
	}
	req := httptest.NewRequest("GET", "/", nil)
	if _, ok := SessionIDFromRequest(req); ok {
		t.Fatal("no cookie")
	}
	req.AddCookie(SessionCookie(id, true, time.Hour))
	if _, ok := SessionIDFromRequest(req); ok {
		t.Fatal("a __Host- cookie was accepted over plain HTTP")
	}
	req.TLS = &tls.ConnectionState{}
	if got, ok := SessionIDFromRequest(req); !ok || got != id {
		t.Fatal("cookie not read")
	}
	plain := httptest.NewRequest("GET", "/", nil)
	plain.AddCookie(SessionCookie(id, false, time.Hour))
	if got, ok := SessionIDFromRequest(plain); !ok || got != id {
		t.Fatal("plain cookie not read over plain HTTP")
	}
	plain.TLS = &tls.ConnectionState{}
	if _, ok := SessionIDFromRequest(plain); ok {
		t.Fatal("a plain cookie was accepted over TLS")
	}
}

func TestCheckOrigin(t *testing.T) {
	mk := func(method, host string, hdr map[string]string) *http.Request {
		r := httptest.NewRequest(method, "https://"+host+"/api/v1/jails", nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	tests := []struct {
		name string
		r    *http.Request
		ok   bool
	}{
		{"get needs nothing", mk("GET", "h:8443", nil), true},
		{"post same origin", mk("POST", "h:8443", map[string]string{"Origin": "https://h:8443"}), true},
		{"post other origin", mk("POST", "h:8443", map[string]string{"Origin": "https://evil.example"}), false},
		{"post other port", mk("POST", "h:8443", map[string]string{"Origin": "https://h:9"}), false},
		{"post no headers", mk("DELETE", "h:8443", nil), false},
		{"null origin falls to referer", mk("POST", "h:8443", map[string]string{"Origin": "null", "Referer": "https://h:8443/ui"}), true},
		{"null origin no referer", mk("POST", "h:8443", map[string]string{"Origin": "null"}), false},
		{"garbage origin", mk("POST", "h:8443", map[string]string{"Origin": "::::"}), false},
	}
	for _, tc := range tests {
		if err := CheckOrigin(tc.r); (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestSeal(t *testing.T) {
	key, _ := NewSealKey()
	sealed, err := Seal(key, []byte("totp-secret"), []byte("user-1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("totp-secret")) {
		t.Fatal("plaintext visible")
	}
	pt, err := Unseal(key, sealed, []byte("user-1"))
	if err != nil || string(pt) != "totp-secret" {
		t.Fatalf("%v %s", err, pt)
	}
	if _, err := Unseal(key, sealed, []byte("user-2")); err == nil {
		t.Fatal("aad not bound")
	}
	other, _ := NewSealKey()
	if _, err := Unseal(other, sealed, []byte("user-1")); err == nil {
		t.Fatal("wrong key")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := Unseal(key, sealed, []byte("user-1")); err == nil {
		t.Fatal("tamper")
	}
	if _, err := Unseal(key, []byte{1}, nil); err == nil {
		t.Fatal("short")
	}
	if _, err := Seal([]byte("short"), nil, nil); err == nil {
		t.Fatal("short key")
	}
	s2, _ := Seal(key, []byte("totp-secret"), []byte("user-1"))
	if bytes.Equal(sealed[:12], s2[:12]) {
		t.Fatal("nonce reuse")
	}
}

func TestLockout(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := NewLockout(LockoutConfig{Now: func() time.Time { return now }, MaxEntries: 3})
	k := "alice|1.2.3.4"
	for i := 1; i <= 4; i++ {
		if err := l.Fail(k); err != nil {
			t.Fatalf("failure %d locked early: %v", i, err)
		}
		if err := l.Check(k); err != nil {
			t.Fatal("locked early")
		}
	}
	err := l.Fail(k)
	var le *LockedError
	if !asLocked(err, &le) || le.RetryAfter != 30*time.Second || le.HTTPStatus() != 429 || le.RetryAfterSeconds() != "30" {
		t.Fatalf("5th failure: %v", err)
	}
	if err := l.Check(k); err == nil {
		t.Fatal("not locked")
	}
	now = now.Add(31 * time.Second)
	if l.Check(k) != nil {
		t.Fatal("still locked after delay")
	}
	// next failure doubles the delay
	err = l.Fail(k)
	if !asLocked(err, &le) || le.RetryAfter != 60*time.Second {
		t.Fatalf("backoff: %v", err)
	}
	// cap
	for range 20 {
		now = now.Add(24 * time.Hour)
		l.Fail(k)
	}
	// 24h > ResetAfter so counters reset; fail quickly many times instead
	for range 30 {
		now = now.Add(time.Minute * 16)
		l.Fail(k)
	}
	if err := l.Fail(k); !asLocked(err, &le) || le.RetryAfter > 15*time.Minute {
		t.Fatalf("cap: %v", err)
	}
	// success clears
	l.Success(k)
	if l.Check(k) != nil || l.Fail(k) != nil {
		t.Fatal("success did not clear")
	}
	// independent keys
	if l.Check("bob|1.2.3.4") != nil {
		t.Fatal("keys leak")
	}
	// quiet period forgets failures
	k2 := "carol"
	for range 4 {
		l.Fail(k2)
	}
	now = now.Add(time.Hour)
	if l.Fail(k2) != nil {
		t.Fatal("old failures counted")
	}
	// bounded table
	for i := range 10 {
		l.Fail(string(rune('a' + i)))
	}
	l.mu.Lock()
	n := len(l.m)
	l.mu.Unlock()
	if n > 3 {
		t.Fatalf("table grew to %d", n)
	}
	if (&LockedError{RetryAfter: 10 * time.Millisecond}).RetryAfterSeconds() != "1" {
		t.Fatal("retry-after rounds up")
	}
}

func asLocked(err error, target **LockedError) bool {
	e, ok := err.(*LockedError)
	if ok {
		*target = e
	}
	return ok
}
