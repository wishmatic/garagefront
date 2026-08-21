package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRequiredFields(t *testing.T) {
	t.Cleanup(func() {
		for _, k := range []string{
			"PUBLIC_HOST", "S3_ENDPOINT", "S3_BUCKET",
			"S3_ACCESS_KEY", "S3_SECRET_KEY", "S3_REGION",
			"HOST", "PORT", "CLOCK_SKEW_SECONDS", "MAX_RESPONSE_BYTES",
			"TRUSTED_SIGNERS", "TLS_CERT_FILE", "TLS_KEY_FILE",
		} {
			_ = os.Unsetenv(k)
		}
	})

	set := func(k, v string) { _ = os.Setenv(k, v) }

	set("PUBLIC_HOST", "cdn.example.com")
	set("S3_ENDPOINT", "https://s3.example.com")
	set("S3_BUCKET", "my-bucket")
	set("S3_REGION", "garage")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg.PublicHost != "cdn.example.com" {
		t.Errorf("PublicHost = %q, want cdn.example.com", cfg.PublicHost)
	}
	if cfg.S3Endpoint != "https://s3.example.com" {
		t.Errorf("S3Endpoint = %q, want https://s3.example.com", cfg.S3Endpoint)
	}
	if cfg.S3Bucket != "my-bucket" {
		t.Errorf("S3Bucket = %q, want my-bucket", cfg.S3Bucket)
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("Host default = %q, want 0.0.0.0", cfg.Host)
	}
	if cfg.Port != 8080 {
		t.Errorf("Port default = %d, want 8080", cfg.Port)
	}
	if cfg.ClockSkewSeconds != 60 {
		t.Errorf("ClockSkewSeconds default = %d, want 60", cfg.ClockSkewSeconds)
	}
	if cfg.MaxResponseBytes != 10485760 {
		t.Errorf("MaxResponseBytes default = %d, want 10485760", cfg.MaxResponseBytes)
	}
}

func TestLoadMissingRequiredFields(t *testing.T) {
	t.Cleanup(func() {
		for _, k := range []string{
			"PUBLIC_HOST", "S3_ENDPOINT", "S3_BUCKET", "TRUSTED_SIGNERS",
		} {
			_ = os.Unsetenv(k)
		}
	})

	for _, tc := range []struct {
		name string
		set  map[string]string
	}{
		{"missing PUBLIC_HOST", map[string]string{"S3_ENDPOINT": "e", "S3_BUCKET": "b", "S3_REGION": "r"}},
		{"missing S3_ENDPOINT", map[string]string{"PUBLIC_HOST": "h", "S3_BUCKET": "b", "S3_REGION": "r"}},
		{"missing S3_BUCKET", map[string]string{"PUBLIC_HOST": "h", "S3_ENDPOINT": "e", "S3_REGION": "r"}},
		{"missing S3_REGION", map[string]string{"PUBLIC_HOST": "h", "S3_ENDPOINT": "e", "S3_BUCKET": "b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"PUBLIC_HOST", "S3_ENDPOINT", "S3_BUCKET", "S3_REGION"} {
				_ = os.Unsetenv(k)
			}
			for k, v := range tc.set {
				_ = os.Setenv(k, v)
			}

			if _, err := Load(); err == nil {
				t.Fatalf("Load() expected error, got nil")
			}
		})
	}
}

func TestLoadTrustedSigners(t *testing.T) {
	dir := t.TempDir()

	pkixPath := writePKIXKey(t, dir, "pkix.pem")
	pkcs1Path := writePKCS1Key(t, dir, "pkcs1.pem")

	signers, err := LoadTrustedSigners("APKA1=" + pkixPath + ",APKA2=" + pkcs1Path)
	if err != nil {
		t.Fatalf("LoadTrustedSigners() unexpected error: %v", err)
	}

	if len(signers) != 2 {
		t.Fatalf("got %d signers, want 2", len(signers))
	}
	if _, ok := signers["APKA1"]; !ok {
		t.Errorf("missing signer APKA1")
	}
	if _, ok := signers["APKA2"]; !ok {
		t.Errorf("missing signer APKA2")
	}
}

func TestLoadTrustedSignersEmpty(t *testing.T) {
	signers, err := LoadTrustedSigners("")
	if err != nil {
		t.Fatalf("LoadTrustedSigners(\"\") unexpected error: %v", err)
	}
	if len(signers) != 0 {
		t.Errorf("got %d signers, want 0", len(signers))
	}
}

func TestLoadTrustedSignersMalformed(t *testing.T) {
	dir := t.TempDir()

	if _, err := LoadTrustedSigners("APKA1=" + filepath.Join(dir, "nope.pem")); err == nil {
		t.Errorf("expected error for missing key file, got nil")
	}

	if _, err := LoadTrustedSigners("APKA1"); err == nil {
		t.Errorf("expected error for malformed entry, got nil")
	}

	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrustedSigners("APKA1=" + bad); err == nil {
		t.Errorf("expected error for non-PEM content, got nil")
	}
}

func writePKIXKey(t *testing.T, dir, name string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return writePEM(t, dir, name, "PUBLIC KEY", der)
}

func writePKCS1Key(t *testing.T, dir, name string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return writePEM(t, dir, name, "RSA PUBLIC KEY", x509.MarshalPKCS1PublicKey(&key.PublicKey))
}

func writePEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	pemData := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRejectsWeakSignerKey(t *testing.T) {
	t.Cleanup(func() {
		for _, k := range []string{
			"PUBLIC_HOST", "S3_ENDPOINT", "S3_BUCKET", "TRUSTED_SIGNERS", "MIN_RSA_KEY_BITS",
		} {
			_ = os.Unsetenv(k)
		}
	})

	dir := t.TempDir()

	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	path := writePEM(t, dir, "weak.pem", "RSA PUBLIC KEY", x509.MarshalPKCS1PublicKey(&weak.PublicKey))

	_ = os.Setenv("PUBLIC_HOST", "cdn.example.com")
	_ = os.Setenv("S3_ENDPOINT", "https://s3.example.com")
	_ = os.Setenv("S3_BUCKET", "my-bucket")
	_ = os.Setenv("S3_REGION", "garage")
	_ = os.Setenv("TRUSTED_SIGNERS", "APKA1="+path)
	_ = os.Setenv("MIN_RSA_KEY_BITS", "2048")

	if _, err := Load(); err == nil {
		t.Fatalf("Load() expected error for weak key, got nil")
	}
}
