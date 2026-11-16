package s3fake_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"jailops.net/jailops/internal/repo/s3"
	"jailops.net/jailops/internal/repo/s3fake"
)

func raw(t *testing.T, srv *s3fake.Server, method, path, query string, body []byte, mod func(*http.Request), signAt time.Time, secret string) (*http.Response, string) {
	t.Helper()
	u := "http://" + srv.Endpoint() + path
	if query != "" {
		u += "?" + query
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		req.Body = http.NoBody
	}
	sum := sha256.Sum256(body)
	cred := s3.Credentials{AccessKey: srv.AccessKey(), SecretKey: secret}
	s3.SignRequest(req, cred, srv.Region(), hex.EncodeToString(sum[:]), signAt)
	if mod != nil {
		mod(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestAuthRefusals(t *testing.T) {
	srv, err := s3fake.New(s3fake.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	_ = srv.EnsureBucket("bkt")
	now := time.Now()
	good := func() (*http.Response, string) {
		return raw(t, srv, "PUT", "/bkt/k", "", []byte("v"), nil, now, srv.SecretKey())
	}
	if r, b := good(); r.StatusCode != 200 {
		t.Fatalf("a good request: %d %s", r.StatusCode, b)
	}
	cases := []struct {
		name string
		code string
		do   func() (*http.Response, string)
	}{
		{"wrong secret", "SignatureDoesNotMatch", func() (*http.Response, string) {
			return raw(t, srv, "PUT", "/bkt/k2", "", []byte("v"), nil, now, "wrong")
		}},
		{"skewed clock", "RequestTimeTooSkewed", func() (*http.Response, string) {
			return raw(t, srv, "PUT", "/bkt/k2", "", []byte("v"), nil, now.Add(-time.Hour), srv.SecretKey())
		}},
		{"tampered path", "SignatureDoesNotMatch", func() (*http.Response, string) {
			return raw(t, srv, "PUT", "/bkt/k2", "", []byte("v"), func(r *http.Request) { r.URL.Path = "/bkt/k3"; r.URL.RawPath = "" }, now, srv.SecretKey())
		}},
		{"tampered query", "SignatureDoesNotMatch", func() (*http.Response, string) {
			return raw(t, srv, "GET", "/bkt", "list-type=2&prefix=a", nil, func(r *http.Request) { r.URL.RawQuery = "list-type=2&prefix=b" }, now, srv.SecretKey())
		}},
		{"unsigned amz header", "AccessDenied", func() (*http.Response, string) {
			return raw(t, srv, "GET", "/bkt/k", "", nil, func(r *http.Request) { r.Header.Set("X-Amz-Meta-Evil", "1") }, now, srv.SecretKey())
		}},
		{"anonymous", "AccessDenied", func() (*http.Response, string) {
			return raw(t, srv, "GET", "/bkt/k", "", nil, func(r *http.Request) { r.Header.Del("Authorization") }, now, srv.SecretKey())
		}},
		{"payload hash mismatch", "XAmzContentSHA256Mismatch", func() (*http.Response, string) {
			return raw(t, srv, "PUT", "/bkt/k2", "", []byte("v"), func(r *http.Request) {
				r.Body = io.NopCloser(strings.NewReader("w"))
			}, now, srv.SecretKey())
		}},
	}
	for _, c := range cases {
		r, b := c.do()
		if r.StatusCode < 400 || !strings.Contains(b, "<Code>"+c.code+"</Code>") {
			t.Errorf("%s: %d %s, want %s", c.name, r.StatusCode, b, c.code)
		}
	}
	if _, ok := srv.Object("bkt", "k2"); ok {
		t.Fatal("a refused request stored an object")
	}
	srv.RemoveUser(srv.AccessKey())
	if r, b := good(); !strings.Contains(b, "InvalidAccessKeyId") {
		t.Fatalf("revoked key: %d %s", r.StatusCode, b)
	}
}

func TestStrictness(t *testing.T) {
	srv, _ := s3fake.New(s3fake.Options{})
	defer srv.Close()
	_ = srv.EnsureBucket("bkt")
	now := time.Now()
	for _, c := range []struct{ method, path, query string }{
		{"POST", "/bkt/k", "uploads="},
		{"PUT", "/bkt/k", "partNumber=1&uploadId=x"},
		{"GET", "/bkt", "versioning="},
		{"GET", "/bkt", "delimiter=%2F&list-type=2"},
		{"GET", "/bkt", ""}, // ListObjectsV1
		{"GET", "/", ""},    // ListBuckets
		{"POST", "/bkt", "delete="},
		{"DELETE", "/bkt/k", "versionId=1"},
	} {
		r, b := raw(t, srv, c.method, c.path, c.query, nil, nil, now, srv.SecretKey())
		if r.StatusCode != 501 {
			t.Errorf("%s %s?%s: %d %s, want 501", c.method, c.path, c.query, r.StatusCode, b)
		}
	}
	for _, h := range []string{"If-Match", "If-Modified-Since", "If-Unmodified-Since"} {
		r, _ := raw(t, srv, "PUT", "/bkt/k", "", []byte("v"), func(r *http.Request) { r.Header.Set(h, "x") }, now, srv.SecretKey())
		if r.StatusCode != 501 {
			t.Errorf("%s answered %d, want 501", h, r.StatusCode)
		}
	}
	r, _ := raw(t, srv, "PUT", "/bkt/k", "", []byte("v"), func(r *http.Request) { r.Header.Set("If-None-Match", "\"abc\"") }, now, srv.SecretKey())
	if r.StatusCode != 501 {
		t.Errorf("a conditional other than * answered %d", r.StatusCode)
	}
}

func TestConditionalPutIsAtomic(t *testing.T) {
	srv, _ := s3fake.New(s3fake.Options{})
	defer srv.Close()
	_ = srv.EnsureBucket("bkt")
	for round := range 5 {
		var ok, fail atomic.Int32
		var wg sync.WaitGroup
		for i := range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, _ := raw(t, srv, "PUT", "/bkt/race"+string(rune('a'+round)), "", []byte{byte(i)}, func(r *http.Request) {
					r.Header.Set("If-None-Match", "*")
				}, time.Now(), srv.SecretKey())
				switch r.StatusCode {
				case 200:
					ok.Add(1)
				case 412:
					fail.Add(1)
				}
			}()
		}
		wg.Wait()
		if ok.Load() != 1 || fail.Load() != 31 {
			t.Fatalf("round %d: %d winners and %d refused of 32", round, ok.Load(), fail.Load())
		}
	}
}

func TestNoTornObjects(t *testing.T) {
	srv, _ := s3fake.New(s3fake.Options{})
	defer srv.Close()
	_ = srv.EnsureBucket("bkt")
	srv.TearNextUpload(1000)
	req, _ := http.NewRequest("PUT", "http://"+srv.Endpoint()+"/bkt/torn", bytes.NewReader(make([]byte, 100000)))
	s3.SignRequest(req, s3.Credentials{AccessKey: srv.AccessKey(), SecretKey: srv.SecretKey()}, srv.Region(), "UNSIGNED-PAYLOAD", time.Now())
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("a torn upload got an answer")
	}
	if _, ok := srv.Object("bkt", "torn"); ok {
		t.Fatal("torn object visible")
	}
	srv.SetQuirk(s3fake.QuirkTornPutVisible, true)
	srv.TearNextUpload(1000)
	req, _ = http.NewRequest("PUT", "http://"+srv.Endpoint()+"/bkt/torn", bytes.NewReader(make([]byte, 100000)))
	s3.SignRequest(req, s3.Credentials{AccessKey: srv.AccessKey(), SecretKey: srv.SecretKey()}, srv.Region(), "UNSIGNED-PAYLOAD", time.Now())
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
	visible := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, visible = srv.Object("bkt", "torn"); visible {
			break
		}
	}
	if !visible {
		t.Fatal("the quirk did not make the torn object visible")
	}
}

func TestRequestLogAndFaults(t *testing.T) {
	srv, _ := s3fake.New(s3fake.Options{})
	defer srv.Close()
	_ = srv.EnsureBucket("bkt")
	rule := srv.FailNth("HeadObject", 2, 503, "SlowDown")
	var codes []int
	for range 3 {
		r, _ := raw(t, srv, "HEAD", "/bkt/x", "", nil, nil, time.Now(), srv.SecretKey())
		codes = append(codes, r.StatusCode)
	}
	if codes[0] != 404 || codes[1] != 503 || codes[2] != 404 || rule.Hits() != 1 {
		t.Fatalf("codes %v hits %d", codes, rule.Hits())
	}
	if srv.Count("HeadObject") != 3 {
		t.Fatalf("count %d", srv.Count("HeadObject"))
	}
	for _, r := range srv.Requests() {
		if strings.Contains(strings.Join(r.Header.Values("Authorization"), ""), srv.SecretKey()) {
			t.Fatal("the secret is in the log")
		}
	}
}

func FuzzParseRangeViaServer(f *testing.F) {
	srv, _ := s3fake.New(s3fake.Options{})
	_ = srv.EnsureBucket("bkt")
	srv.PutDirect("bkt", "o", []byte("0123456789"), time.Now())
	f.Cleanup(srv.Close)
	f.Add("bytes=0-3")
	f.Add("bytes=-4")
	f.Add("bytes=5-")
	f.Add("bytes=9-2")
	f.Add("lines=1")
	f.Fuzz(func(t *testing.T, rng string) {
		if strings.ContainsAny(rng, "\r\n\x00") {
			return
		}
		req, _ := http.NewRequest("GET", "http://"+srv.Endpoint()+"/bkt/o", nil)
		req.Header.Set("Range", rng)
		s3.SignRequest(req, s3.Credentials{AccessKey: srv.AccessKey(), SecretKey: srv.SecretKey()}, srv.Region(), "", time.Now())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if len(b) > 10 {
			t.Fatalf("range %q returned %d bytes of a 10 byte object", rng, len(b))
		}
	})
}
