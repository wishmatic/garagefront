package cookie

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const keyPairID = "APKA1234"

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, key *rsa.PrivateKey, payload []byte, hash crypto.Hash) []byte {
	t.Helper()
	var digest []byte
	switch hash {
	case crypto.SHA1:
		h := sha1.Sum(payload)
		digest = h[:]
	case crypto.SHA256:
		h := sha256.Sum256(payload)
		digest = h[:]
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

var b64Std = base64.StdEncoding

// cfBase64 encodes bytes using the CloudFront base64 variant: '+' -> '-', '/' -> '~', '=' -> '_'.
func cfBase64(b []byte) string {
	s := b64Std.EncodeToString(b)
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "~")
	s = strings.ReplaceAll(s, "=", "_")
	return s
}

// signedCookie builds the three cookie values for a resource/expiry, signing the raw JSON policy exactly as
// `@aws-sdk/cloudfront-signer` does.
func signedCookie(t *testing.T, key *rsa.PrivateKey, hash crypto.Hash, resource string, expires int64) map[string]string {
	t.Helper()
	policyJSON := mustPolicy(resource, expires)
	sig := sign(t, key, policyJSON, hash)
	return map[string]string{
		"CloudFront-Key-Pair-Id": keyPairID,
		"CloudFront-Policy":      cfBase64(policyJSON),
		"CloudFront-Signature":   cfBase64(sig),
	}
}

func request(path string, cookies map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://cdn.example.com"+path, nil)
	for k, v := range cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	return r
}

func mustPolicy(resource string, expires int64) []byte {
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
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return b
}

func TestVerifySHA256(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60)

	r := request(
		"/i/user/1.png",
		signedCookie(t, key, crypto.SHA256, "https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix()),
	)
	if err := v.Verify(r); err != nil {
		t.Fatalf("Verify() = %v, want nil", err)
	}
}

func TestVerifySHA1(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60)

	r := request(
		"/i/user/1.png",
		signedCookie(t, key, crypto.SHA1, "https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix()),
	)
	if err := v.Verify(r); err != nil {
		t.Fatalf("Verify() = %v, want nil", err)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	key := newKey(t)
	other := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &other.PublicKey}, 60)

	r := request(
		"/i/user/1.png",
		signedCookie(t, key, crypto.SHA256, "https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix()),
	)
	if err := v.Verify(r); err != ErrAccessDenied {
		t.Fatalf("Verify() = %v, want ErrAccessDenied", err)
	}
}

func TestVerifyTamperedPayload(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60)

	cookies := signedCookie(t, key, crypto.SHA256, "https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix())
	policy := cookies["CloudFront-Policy"]
	cookies["CloudFront-Policy"] = policy[:len(policy)-2] + "AA"

	r := request("/i/user/1.png", cookies)
	if err := v.Verify(r); err != ErrAccessDenied {
		t.Fatalf("Verify() = %v, want ErrAccessDenied", err)
	}
}

func TestResourceMatching(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60)

	mk := func(resource, path string) *http.Request {
		return request(path, signedCookie(t, key, crypto.SHA256, resource, time.Now().Add(time.Hour).Unix()))
	}

	if err := v.Verify(mk("https://cdn.example.com/i/*", "/i/user/1.png")); err != nil {
		t.Errorf("wildcard /i/* should match /i/user/1.png: %v", err)
	}
	if err := v.Verify(mk("https://cdn.example.com/i/*", "/a/x.png")); err != ErrAccessDenied {
		t.Errorf("wildcard /i/* should reject /a/x.png, got %v", err)
	}
	if err := v.Verify(mk("https://cdn.example.com/i/user/1.png", "/i/user/1.png")); err != nil {
		t.Errorf("exact path should match: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60)

	mk := func(expires int64) *http.Request {
		return request("/i/user/1.png", signedCookie(t, key, crypto.SHA256, "https://cdn.example.com/i/*", expires))
	}

	if err := v.Verify(mk(time.Now().Add(-2 * time.Minute).Unix())); err != ErrAccessDenied {
		t.Errorf("expired policy should be rejected, got %v", err)
	}
	if err := v.Verify(mk(time.Now().Add(time.Hour).Unix())); err != nil {
		t.Errorf("future expiry should be accepted: %v", err)
	}
}

func TestMissingFields(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60)

	if err := v.Verify(request("/i/a.png", nil)); err != ErrMissingKeyPairID {
		t.Errorf("missing key-pair-id = %v, want ErrMissingKeyPairID", err)
	}

	cookies := signedCookie(t, key, crypto.SHA256, "https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix())

	// Missing signature.

	noSig := map[string]string{
		"CloudFront-Key-Pair-Id": cookies["CloudFront-Key-Pair-Id"],
		"CloudFront-Policy":      cookies["CloudFront-Policy"],
	}
	if err := v.Verify(request("/i/a.png", noSig)); err != ErrAccessDenied {
		t.Errorf("missing signature = %v, want ErrAccessDenied", err)
	}

	// Missing policy.

	noPolicy := map[string]string{
		"CloudFront-Key-Pair-Id": cookies["CloudFront-Key-Pair-Id"],
		"CloudFront-Signature":   cookies["CloudFront-Signature"],
	}
	if err := v.Verify(request("/i/a.png", noPolicy)); err != ErrAccessDenied {
		t.Errorf("missing policy = %v, want ErrAccessDenied", err)
	}

	// Wrong key-pair-id.

	wrongID := map[string]string{
		"CloudFront-Key-Pair-Id": "WRONG",
		"CloudFront-Policy":      cookies["CloudFront-Policy"],
		"CloudFront-Signature":   cookies["CloudFront-Signature"],
	}
	if err := v.Verify(request("/i/a.png", wrongID)); err != ErrAccessDenied {
		t.Errorf("wrong key-pair-id = %v, want ErrAccessDenied", err)
	}
}

func TestVerifyRejectsWrongHost(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60, WithPublicHost("cdn.example.com"))

	r := request(
		"/i/a.png",
		signedCookie(
			t, key, crypto.SHA256, "https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix(),
		),
	)
	r.Host = "evil.example.com"

	if err := v.Verify(r); err != ErrAccessDenied {
		t.Errorf("Verify() = %v, want ErrAccessDenied", err)
	}
}

func TestVerifyPublicHostAsFullURL(t *testing.T) {
	key := newKey(t)

	// PUBLIC_HOST may be configured as a full URL; the verifier must reduce it to the bare host.

	v := NewVerifier(
		map[string]*rsa.PublicKey{keyPairID: &key.PublicKey},
		60,
		WithPublicHost("https://cdn.example.com/"),
	)

	r := request(
		"/i/a.png",
		signedCookie(
			t, key, crypto.SHA256, "https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix(),
		),
	)

	if err := v.Verify(r); err != nil {
		t.Errorf("Verify() with full-URL PUBLIC_HOST = %v, want nil", err)
	}
}

func TestVerifyForceSchemeHTTPS(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60, WithForceSchemeHTTPS(true))

	cookies := signedCookie(t, key, crypto.SHA256, "https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix())

	// Plain-HTTP request (no TLS), but forced scheme treats it as https.

	r := httptest.NewRequest(http.MethodGet, "http://cdn.example.com/i/a.png", nil)
	for k, v := range cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	if err := v.Verify(r); err != nil {
		t.Errorf("Verify() with forced HTTPS = %v, want nil", err)
	}
}
