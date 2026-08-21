package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// TrustedSigners maps a CloudFront Key-Pair-Id to its RSA public key.
type TrustedSigners map[string]*rsa.PublicKey

// UnmarshalText implements encoding.TextUnmarshaler so the env parser can populate TrustedSigners from a
// TRUSTED_SIGNERS value directly.
func (t *TrustedSigners) UnmarshalText(text []byte) error {
	signers, err := LoadTrustedSigners(string(text))
	if err != nil {
		return err
	}
	*t = signers
	return nil
}

func LoadTrustedSigners(raw string) (TrustedSigners, error) {
	return loadTrustedSigners(raw, 0)
}

func loadTrustedSigners(raw string, minBits int) (TrustedSigners, error) {
	signers := TrustedSigners{}
	if strings.TrimSpace(raw) == "" {
		return signers, nil
	}

	entries := strings.Split(raw, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		keyPairID, path, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("invalid trusted signer entry %q: expected keypairid=/path/to/key.pem", entry)
		}
		keyPairID = strings.TrimSpace(keyPairID)
		path = strings.TrimSpace(path)
		if keyPairID == "" || path == "" {
			return nil, fmt.Errorf("invalid trusted signer entry %q: empty key-pair-id or path", entry)
		}

		key, err := loadRSAPublicKey(path, minBits)
		if err != nil {
			return nil, fmt.Errorf("load public key for %q: %w", keyPairID, err)
		}
		signers[keyPairID] = key
	}

	return signers, nil
}

func loadRSAPublicKey(path string, minBits int) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	var pub any
	switch block.Type {
	case "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an RSA key (got %T)", pub)
	}

	if minBits > 0 && rsaPub.N.BitLen() < minBits {
		return nil, fmt.Errorf("public key is %d bits, below minimum %d", rsaPub.N.BitLen(), minBits)
	}

	return rsaPub, nil
}
