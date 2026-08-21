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

func customCookie(t *testing.T, key *rsa.PrivateKey, hash crypto.Hash, resource string, expires int64) string {
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
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	policy := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(raw)
	sig := sign(t, key, []byte(policy), hash)
	return base64.RawURLEncoding.EncodeToString(sig)
}

func request(path string, cookies map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://cdn.example.com"+path, nil)
	for k, v := range cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	return r
}

func TestVerifyCustomPolicySHA256(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60)

	policy := base64.RawURLEncoding.EncodeToString(
		mustPolicy("https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix()),
	)
	sig := sign(t, key, []byte(policy), crypto.SHA256)
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)

	r := request("/i/user/1.png", map[string]string{
		"CloudFront-Key-Pair-Id": keyPairID,
		"CloudFront-Policy":      policy,
		"CloudFront-Signature":   sigEnc,
	})
	if err := v.Verify(r); err != nil {
		t.Fatalf("Verify() = %v, want nil", err)
	}
}

func TestVerifyCustomPolicySHA1(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60)

	policy := base64.RawURLEncoding.EncodeToString(
		mustPolicy("https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix()),
	)
	sig := sign(t, key, []byte(policy), crypto.SHA1)
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)

	r := request("/i/user/1.png", map[string]string{
		"CloudFront-Key-Pair-Id": keyPairID,
		"CloudFront-Policy":      policy,
		"CloudFront-Signature":   sigEnc,
	})
	if err := v.Verify(r); err != nil {
		t.Fatalf("Verify() = %v, want nil", err)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	key := newKey(t)
	other := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &other.PublicKey}, 60)

	policy := base64.RawURLEncoding.EncodeToString(
		mustPolicy("https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix()),
	)
	sig := sign(t, key, []byte(policy), crypto.SHA256)

	r := request("/i/user/1.png", map[string]string{
		"CloudFront-Key-Pair-Id": keyPairID,
		"CloudFront-Policy":      policy,
		"CloudFront-Signature":   base64.RawURLEncoding.EncodeToString(sig),
	})
	if err := v.Verify(r); err != ErrAccessDenied {
		t.Fatalf("Verify() = %v, want ErrAccessDenied", err)
	}
}

func TestVerifyTamperedPayload(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60)

	policy := base64.RawURLEncoding.EncodeToString(
		mustPolicy("https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix()),
	)
	sig := sign(t, key, []byte(policy), crypto.SHA256)

	tampered := policy[:len(policy)-4] + "AAAA"

	r := request("/i/user/1.png", map[string]string{
		"CloudFront-Key-Pair-Id": keyPairID,
		"CloudFront-Policy":      tampered,
		"CloudFront-Signature":   base64.RawURLEncoding.EncodeToString(sig),
	})
	if err := v.Verify(r); err != ErrAccessDenied {
		t.Fatalf("Verify() = %v, want ErrAccessDenied", err)
	}
}

func TestResourceMatching(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60)

	mk := func(resource, path string) *http.Request {
		policy := base64.RawURLEncoding.EncodeToString(mustPolicy(resource, time.Now().Add(time.Hour).Unix()))
		sig := sign(t, key, []byte(policy), crypto.SHA256)
		return request(path, map[string]string{
			"CloudFront-Key-Pair-Id": keyPairID,
			"CloudFront-Policy":      policy,
			"CloudFront-Signature":   base64.RawURLEncoding.EncodeToString(sig),
		})
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
		policy := base64.RawURLEncoding.EncodeToString(mustPolicy("https://cdn.example.com/i/*", expires))
		sig := sign(t, key, []byte(policy), crypto.SHA256)
		return request("/i/user/1.png", map[string]string{
			"CloudFront-Key-Pair-Id": keyPairID,
			"CloudFront-Policy":      policy,
			"CloudFront-Signature":   base64.RawURLEncoding.EncodeToString(sig),
		})
	}

	if err := v.Verify(mk(time.Now().Add(-2 * time.Minute).Unix())); err != ErrAccessDenied {
		t.Errorf("expired policy should be rejected, got %v", err)
	}
	if err := v.Verify(mk(time.Now().Add(time.Hour).Unix())); err != nil {
		t.Errorf("future expiry should be accepted: %v", err)
	}
}

func TestBase64Variants(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60)

	raw := mustPolicy("https://cdn.example.com/i/*", time.Now().Add(time.Hour).Unix())

	encode := []struct {
		name string
		enc  func([]byte) string
	}{
		{"standard padded", base64.StdEncoding.EncodeToString},
		{"standard unpadded", base64.RawStdEncoding.EncodeToString},
		{"urlsafe padded", base64.URLEncoding.EncodeToString},
		{"urlsafe unpadded", base64.RawURLEncoding.EncodeToString},
	}

	for _, e := range encode {
		t.Run(e.name, func(t *testing.T) {
			policy := e.enc(raw)
			sig := sign(t, key, []byte(policy), crypto.SHA256)
			r := request("/i/user/1.png", map[string]string{
				"CloudFront-Key-Pair-Id": keyPairID,
				"CloudFront-Policy":      policy,
				"CloudFront-Signature":   e.enc(sig),
			})
			if err := v.Verify(r); err != nil {
				t.Fatalf("Verify() = %v, want nil", err)
			}
		})
	}
}

func TestMissingFields(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60)

	if err := v.Verify(request("/i/a.png", nil)); err != ErrMissingKeyPairID {
		t.Errorf("missing key-pair-id = %v, want ErrMissingKeyPairID", err)
	}

	policy := base64.RawURLEncoding.EncodeToString(mustPolicy(
		"https://cdn.example.com/i/*",
		time.Now().Add(time.Hour).Unix(),
	))
	sig := sign(t, key, []byte(policy), crypto.SHA256)

	if err := v.Verify(request("/i/a.png", map[string]string{
		"CloudFront-Key-Pair-Id": keyPairID,
		"CloudFront-Policy":      policy,
	})); err != ErrAccessDenied {
		t.Errorf("missing signature = %v, want ErrAccessDenied", err)
	}

	if err := v.Verify(request("/i/a.png", map[string]string{
		"CloudFront-Key-Pair-Id": "WRONG",
		"CloudFront-Policy":      policy,
		"CloudFront-Signature":   base64.RawURLEncoding.EncodeToString(sig),
	})); err != ErrAccessDenied {
		t.Errorf("wrong key-pair-id = %v, want ErrAccessDenied", err)
	}
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

func TestVerifyRejectsWrongHost(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60, WithPublicHost("cdn.example.com"))

	policy := base64.RawURLEncoding.EncodeToString(mustPolicy(
		"https://cdn.example.com/i/*",
		time.Now().Add(time.Hour).Unix(),
	))
	sig := base64.RawURLEncoding.EncodeToString(sign(t, key, []byte(policy), crypto.SHA256))

	r := request("/i/a.png", map[string]string{
		"CloudFront-Key-Pair-Id": keyPairID,
		"CloudFront-Policy":      policy,
		"CloudFront-Signature":   sig,
	})
	r.Host = "evil.example.com"

	if err := v.Verify(r); err != ErrAccessDenied {
		t.Errorf("Verify() = %v, want ErrAccessDenied", err)
	}
}

func TestVerifyMultiStatementUsesMaxExpiry(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60)

	// First statement expires far in the future, second (matching) also in the future.
	// A single-statement naive check would only look at the first.

	doc := map[string]any{
		"Statement": []any{
			map[string]any{
				"Resource": "https://cdn.example.com/other/*",
				"Condition": map[string]any{
					"DateLessThan": map[string]any{"AWS:EpochTime": time.Now().Add(24 * time.Hour).Unix()},
				},
			},
			map[string]any{
				"Resource": "https://cdn.example.com/i/*",
				"Condition": map[string]any{
					"DateLessThan": map[string]any{"AWS:EpochTime": time.Now().Add(1 * time.Hour).Unix()},
				},
			},
		},
	}
	raw, _ := json.Marshal(doc)
	policy := base64.RawURLEncoding.EncodeToString(raw)
	sig := base64.RawURLEncoding.EncodeToString(sign(t, key, []byte(policy), crypto.SHA256))

	r := request("/i/a.png", map[string]string{
		"CloudFront-Key-Pair-Id": keyPairID,
		"CloudFront-Policy":      policy,
		"CloudFront-Signature":   sig,
	})

	if err := v.Verify(r); err != nil {
		t.Errorf("Verify() = %v, want nil", err)
	}
}

func TestVerifyForceSchemeHTTPS(t *testing.T) {
	key := newKey(t)
	v := NewVerifier(map[string]*rsa.PublicKey{keyPairID: &key.PublicKey}, 60, WithForceSchemeHTTPS(true))

	policy := base64.RawURLEncoding.EncodeToString(mustPolicy(
		"https://cdn.example.com/i/*",
		time.Now().Add(time.Hour).Unix(),
	))
	sig := base64.RawURLEncoding.EncodeToString(sign(t, key, []byte(policy), crypto.SHA256))

	// Plain-HTTP request (no TLS), but forced scheme treats it as https.

	r := httptest.NewRequest(http.MethodGet, "http://cdn.example.com/i/a.png", nil)
	r.AddCookie(&http.Cookie{Name: "CloudFront-Key-Pair-Id", Value: keyPairID})
	r.AddCookie(&http.Cookie{Name: "CloudFront-Policy", Value: policy})
	r.AddCookie(&http.Cookie{Name: "CloudFront-Signature", Value: sig})

	if err := v.Verify(r); err != nil {
		t.Errorf("Verify() with forced HTTPS = %v, want nil", err)
	}
}
