package cookie

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Verifier struct {
	keys             map[string]*rsa.PublicKey
	clockSkew        time.Duration
	publicHost       string
	forceSchemeHTTPS bool
}

// policy mirrors the JSON policy signed into CloudFront-Policy. LibreChat emits exactly one Statement with a Resource
// and a DateLessThan condition; we parse only those fields.
type policy struct {
	Statement []struct {
		Resource  string `json:"Resource"`
		Condition struct {
			DateLessThan struct {
				AwsEpochTime int64 `json:"AWS:EpochTime"`
			} `json:"DateLessThan"`
		} `json:"Condition"`
	} `json:"Statement"`
}

type VerifierOption func(*Verifier)

func WithPublicHost(host string) VerifierOption {
	return func(v *Verifier) {
		v.publicHost = host
	}
}

func WithForceSchemeHTTPS(force bool) VerifierOption {
	return func(v *Verifier) {
		v.forceSchemeHTTPS = force
	}
}

func NewVerifier(keys map[string]*rsa.PublicKey, clockSkewSeconds int, opts ...VerifierOption) *Verifier {
	v := &Verifier{
		keys:      keys,
		clockSkew: time.Duration(clockSkewSeconds) * time.Second,
	}

	for _, opt := range opts {
		opt(v)
	}

	return v
}

func (v *Verifier) Verify(r *http.Request) error {
	if v.publicHost != "" && !strings.EqualFold(r.Host, v.publicHost) {
		return ErrAccessDenied
	}

	keyPairID := cookieValue(r, "CloudFront-Key-Pair-Id")
	if keyPairID == "" {
		return ErrMissingKeyPairID
	}

	key, ok := v.keys[keyPairID]
	if !ok {
		return ErrAccessDenied
	}

	signature := cookieValue(r, "CloudFront-Signature")
	if signature == "" {
		return ErrAccessDenied
	}

	policyVal := cookieValue(r, "CloudFront-Policy")
	if policyVal == "" {
		return ErrAccessDenied
	}

	policyJSON, err := base64Decode(policyVal)
	if err != nil {
		return ErrAccessDenied
	}

	sigBytes, err := base64Decode(signature)
	if err != nil {
		return ErrAccessDenied
	}

	// The signature is over the raw JSON policy (before base64 encoding). Verify it before parsing any
	// attacker-controlled policy fields, so unauthenticated requests cannot force JSON parsing work.
	if !verifySig(key, policyJSON, sigBytes) {
		return ErrAccessDenied
	}

	var p policy
	if err := json.Unmarshal(policyJSON, &p); err != nil || len(p.Statement) == 0 {
		return ErrAccessDenied
	}

	resource := p.Statement[0].Resource
	expiresAt := p.Statement[0].Condition.DateLessThan.AwsEpochTime
	if resource == "" || expiresAt == 0 {
		return ErrAccessDenied
	}

	if time.Now().After(time.Unix(expiresAt, 0).Add(v.clockSkew)) {
		return ErrAccessDenied
	}

	if !v.resourceMatches(r, resource) {
		return ErrAccessDenied
	}

	return nil
}

// verifySig verifies the RSA PKCS#1 v1.5 signature over payload. LibreChat signs with SHA-1 by default (it never
// passes `algorithm` to @aws-sdk/cloudfront-signer), so SHA-1 is tried first; SHA-256 is kept for forward
// compatibility.
func verifySig(key *rsa.PublicKey, payload, sig []byte) bool {
	sha1Hashed := sha1.Sum(payload)
	if rsa.VerifyPKCS1v15(key, crypto.SHA1, sha1Hashed[:], sig) == nil {
		return true
	}

	hashed := sha256.Sum256(payload)

	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], sig) == nil
}

func (v *Verifier) resourceMatches(r *http.Request, resource string) bool {
	u, err := url.Parse(resource)
	if err != nil {
		return false
	}

	if u.Scheme != v.scheme(r) || !strings.EqualFold(u.Host, r.Host) {
		return false
	}

	return globMatch(u.Path, r.URL.Path)
}

func (v *Verifier) scheme(r *http.Request) string {
	if v.forceSchemeHTTPS {
		return "https"
	}

	if r.TLS != nil {
		return "https"
	}

	if r.URL.Scheme == "https" {
		return "https"
	}

	return "http"
}

func globMatch(pattern, target string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == target
	}

	return globMatchRecursive(pattern, target)
}

func globMatchRecursive(pattern, target string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			for i := 0; i <= len(target); i++ {
				if globMatchRecursive(pattern[1:], target[i:]) {
					return true
				}
			}

			return false
		default:
			if len(target) == 0 || pattern[0] != target[0] {
				return false
			}

			pattern = pattern[1:]
			target = target[1:]
		}
	}

	return len(target) == 0
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}

	return c.Value
}

// base64Decode decodes the CloudFront base64 variant, which differs from both
// standard and URL-safe base64: '+' -> '-', '/' -> '~', '=' -> '_'.
func base64Decode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "~", "/")
	s = strings.ReplaceAll(s, "_", "=")

	return base64.StdEncoding.DecodeString(s)
}
