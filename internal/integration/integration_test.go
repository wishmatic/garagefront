package integration

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/wishmatic/garagefront/internal/config"
	"github.com/wishmatic/garagefront/internal/server"
	"github.com/wishmatic/garagefront/internal/storage"
)

const testKeyPairID = "APKA1234"

// repoRoot resolves the repository root from the location of this source file, so the test can reach the committed
// fixtures under data/tests/.
func repoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve source file path")
	}

	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(repoRoot(t), "data", "tests", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}

	return data
}

func loadTestPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()

	block, _ := pem.Decode(readFixture(t, "test_public.pem"))
	if block == nil {
		t.Fatal("no PEM block in test public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *rsa.PublicKey", pub)
	}

	return rsaPub
}

func loadCookieFixture(t *testing.T) map[string]string {
	t.Helper()

	var cookies map[string]string

	if err := json.Unmarshal(readFixture(t, "cookies.json"), &cookies); err != nil {
		t.Fatalf("unmarshal cookie fixture: %v", err)
	}

	return cookies
}

// newFakeGarage is an in-process S3-compatible stub that serves a single canned object for any key. It ignores SigV4
// auth; the storage client signs requests but the stub doesn't validate them.
func newFakeGarage(t *testing.T) *httptest.Server {
	t.Helper()
	body := []byte("hello from garage")
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("ETag", `"abc123"`)
		w.Header().Set("Last-Modified", "Mon, 01 Jan 2024 00:00:00 GMT")
		w.Header().Set("Content-Length", strconv.FormatInt(int64(len(body)), 10))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
}

func newTestServer(t *testing.T, garageURL string, pub *rsa.PublicKey) *server.Server {
	t.Helper()

	cfg := config.Config{
		Host:             "127.0.0.1",
		Port:             0,
		PublicHost:       "cdn.example.com",
		ClockSkewSeconds: 60,
		ForceSchemeHTTPS: true,
		TrustedSigners:   config.TrustedSigners{testKeyPairID: pub},
	}

	store := storage.NewClient(garageURL, "test-bucket", "garage", "test-access", "test-secret")
	logger := log.New(io.Discard, "", 0)

	return server.New(cfg, store, logger)
}

func doGet(t *testing.T, s *server.Server, path string, cookies map[string]string) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://cdn.example.com"+path, nil)
	req.Host = "cdn.example.com"

	for k, v := range cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	return rec.Result()
}

func TestRealSignerRoundTrip(t *testing.T) {
	pub := loadTestPublicKey(t)
	cookies := loadCookieFixture(t)
	garage := newFakeGarage(t)

	defer garage.Close()

	s := newTestServer(t, garage.URL, pub)

	resp1 := doGet(t, s, "/i/images/user123/file.png", cookies)
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("signed request status = %d, want 200", resp1.StatusCode)
	}

	if got := resp1.Header.Get("Content-Type"); got != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", got)
	}

	if got := resp1.Header.Get("ETag"); got != `"abc123"` {
		t.Errorf("ETag = %q, want \"abc123\"", got)
	}

	body, _ := io.ReadAll(resp1.Body)
	if string(body) != "hello from garage" {
		t.Errorf("body = %q, want \"hello from garage\"", string(body))
	}

	resp2 := doGet(t, s, "/i/images/user123/file.png", nil)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("unsigned request status = %d, want 403", resp2.StatusCode)
	}

	tampered := make(map[string]string, len(cookies))

	maps.Copy(tampered, cookies)
	sig := tampered["CloudFront-Signature"]
	tampered["CloudFront-Signature"] = sig[:len(sig)-2] + "AA"

	resp3 := doGet(t, s, "/i/images/user123/file.png", tampered)
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusForbidden {
		t.Fatalf("tampered-signature request status = %d, want 403", resp3.StatusCode)
	}
}
