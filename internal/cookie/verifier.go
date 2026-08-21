package cookie

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Verifier struct {
	keys             map[string]*rsa.PublicKey
	clockSkew        time.Duration
	publicHost       string
	forceSchemeHTTPS bool
}

type policy struct {
	Statements []statement `json:"Statement"`
}

type statement struct {
	Resource  string    `json:"Resource"`
	Condition condition `json:"Condition"`
}

type condition struct {
	DateLessThan dateLessThan `json:"DateLessThan"`
}

type dateLessThan struct {
	AwsEpochTime int64 `json:"AWS:EpochTime"`
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
	expiresVal := cookieValue(r, "CloudFront-Expires")

	var payload []byte
	var resources []string
	var expiresAt int64

	switch {
	case policyVal != "":
		payload = []byte(policyVal)

		decoded, err := base64Decode(policyVal)
		if err != nil {
			return ErrAccessDenied
		}

		var p policy
		if err := json.Unmarshal(decoded, &p); err != nil || len(p.Statements) == 0 {
			return ErrAccessDenied
		}

		for _, s := range p.Statements {
			resources = append(resources, s.Resource)
			if s.Condition.DateLessThan.AwsEpochTime > expiresAt {
				expiresAt = s.Condition.DateLessThan.AwsEpochTime
			}
		}
	case expiresVal != "":
		expires, err := strconv.ParseInt(expiresVal, 10, 64)
		if err != nil {
			return ErrAccessDenied
		}

		expiresAt = expires

		payload, resources = v.cannedPolicy(r, expires)
	default:
		return ErrAccessDenied
	}

	if expiresAt == 0 {
		return ErrAccessDenied
	}

	sigBytes, err := base64Decode(signature)
	if err != nil {
		return ErrAccessDenied
	}

	if !verifySig(key, payload, sigBytes) {
		return ErrAccessDenied
	}

	if time.Now().After(time.Unix(expiresAt, 0).Add(v.clockSkew)) {
		return ErrAccessDenied
	}

	if !v.resourceMatches(r, resources) {
		return ErrAccessDenied
	}

	return nil
}

func (v *Verifier) cannedPolicy(r *http.Request, expires int64) ([]byte, []string) {
	resource := fmt.Sprintf("%s://%s%s", v.scheme(r), r.Host, r.URL.Path)

	doc := policy{
		Statements: []statement{
			{
				Resource: resource,
				Condition: condition{
					DateLessThan: dateLessThan{AwsEpochTime: expires},
				},
			},
		},
	}
	b, _ := json.Marshal(doc)

	return b, []string{resource}
}

func verifySig(key *rsa.PublicKey, payload, sig []byte) bool {
	hashed := sha256.Sum256(payload)

	if rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], sig) == nil {
		return true
	}

	sha1Hashed := sha1.Sum(payload)

	return rsa.VerifyPKCS1v15(key, crypto.SHA1, sha1Hashed[:], sig) == nil
}

func (v *Verifier) resourceMatches(r *http.Request, resources []string) bool {
	for _, res := range resources {
		u, err := url.Parse(res)
		if err != nil {
			continue
		}
		if u.Scheme != v.scheme(r) || u.Host != r.Host {
			continue
		}
		if globMatch(u.Path, r.URL.Path) {
			return true
		}
	}

	return false
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

func base64Decode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	return base64.StdEncoding.DecodeString(s)
}
