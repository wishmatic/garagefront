package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wishmatic/garagefront/internal/config"
	"github.com/wishmatic/garagefront/internal/storage"
)

const keyPairID = "APKA1234"

var base64Std = base64.StdEncoding

type fakeStore struct {
	obj *storage.Object
	err error
}

func (f *fakeStore) Get(ctx context.Context, key string) (*storage.Object, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.obj, nil
}

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func cfBase64(b []byte) string {
	s := base64Std.EncodeToString(b)
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "~")
	s = strings.ReplaceAll(s, "=", "_")
	return s
}

func signedCookies(t *testing.T, key *rsa.PrivateKey, resource string, expires int64) map[string]string {
	t.Helper()
	doc := map[string]any{
		"Statement": []any{
			map[string]any{
				"Resource": resource,
				"Condition": map[string]any{
					"DateLessThan": map[string]any{"AWS:EpochTime": expires},
				},
			},
		},
	}
	policyJSON, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha1.Sum(policyJSON)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	return map[string]string{
		"CloudFront-Key-Pair-Id": keyPairID,
		"CloudFront-Policy":      cfBase64(policyJSON),
		"CloudFront-Signature":   cfBase64(sig),
	}
}

func testServer(t *testing.T, key *rsa.PrivateKey, store *fakeStore) *Server {
	t.Helper()
	cfg := config.Config{
		PublicHost:       "cdn.example.com",
		ClockSkewSeconds: 60,
		ForceSchemeHTTPS: true,
		TrustedSigners:   config.TrustedSigners{keyPairID: &key.PublicKey},
	}
	logger := log.New(io.Discard, "", 0)
	return New(cfg, store, logger)
}

func doRequest(t *testing.T, s *Server, path string, cookies map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://cdn.example.com"+path, nil)
	req.Host = "cdn.example.com"
	for k, v := range cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	rec := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rec, req)
	return rec
}

func TestMissingCookieReturns403(t *testing.T) {
	key := newKey(t)
	s := testServer(t, key, &fakeStore{})

	rec := doRequest(t, s, "/i/images/user/1.png", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestValidCookieServesObject(t *testing.T) {
	key := newKey(t)
	body := []byte("hello world")
	store := &fakeStore{
		obj: &storage.Object{
			Body:         io.NopCloser(bytes.NewReader(body)),
			ContentType:  "image/png",
			ContentLen:   int64(len(body)),
			ETag:         `"abc123"`,
			LastModified: "Mon, 01 Jan 2024 00:00:00 GMT",
		},
	}
	s := testServer(t, key, store)

	cookies := signedCookies(t, key, "https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix())
	rec := doRequest(t, s, "/i/images/user/1.png", cookies)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != string(body) {
		t.Errorf("body = %q, want %q", rec.Body.String(), string(body))
	}
	if rec.Header().Get("Content-Type") != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("ETag") != `"abc123"` {
		t.Errorf("ETag = %q, want \"abc123\"", rec.Header().Get("ETag"))
	}
	if rec.Header().Get("Last-Modified") != "Mon, 01 Jan 2024 00:00:00 GMT" {
		t.Errorf("Last-Modified = %q", rec.Header().Get("Last-Modified"))
	}
	if rec.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'none'" {
		t.Errorf("Content-Security-Policy = %q, want default-src 'none'", got)
	}
}

func TestWrongResourceReturns403(t *testing.T) {
	key := newKey(t)
	store := &fakeStore{
		obj: &storage.Object{
			Body:         io.NopCloser(bytes.NewReader([]byte("x"))),
			ContentType:  "image/png",
			ContentLen:   1,
			ETag:         `"e"`,
			LastModified: "Mon, 01 Jan 2024 00:00:00 GMT",
		},
	}
	s := testServer(t, key, store)

	// Cookie scoped to /a/*, request to /i/.
	cookies := signedCookies(t, key, "https://cdn.example.com/a/*", time.Now().Add(time.Hour).Unix())
	rec := doRequest(t, s, "/i/images/user/1.png", cookies)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestNotFoundReturns404(t *testing.T) {
	key := newKey(t)
	store := &fakeStore{err: storage.ErrNotFound}
	s := testServer(t, key, store)

	cookies := signedCookies(t, key, "https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix())
	rec := doRequest(t, s, "/i/images/user/1.png", cookies)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestForbiddenReturns403(t *testing.T) {
	key := newKey(t)
	store := &fakeStore{err: storage.ErrForbidden}
	s := testServer(t, key, store)

	cookies := signedCookies(t, key, "https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix())
	rec := doRequest(t, s, "/i/images/user/1.png", cookies)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestUpstreamErrorReturns502(t *testing.T) {
	key := newKey(t)
	store := &fakeStore{err: errors.New("boom")}
	s := testServer(t, key, store)

	cookies := signedCookies(t, key, "https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix())
	rec := doRequest(t, s, "/i/images/user/1.png", cookies)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}
