package config

import (
	"fmt"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	Host string `env:"HOST" envDefault:"0.0.0.0"`
	Port int    `env:"PORT" envDefault:"8080"`

	// Public hostname and TLS. PublicHost must equal the host portion of the CloudFront domain.

	PublicHost  string `env:"PUBLIC_HOST,required"`
	TLSCertFile string `env:"TLS_CERT_FILE"`
	TLSKeyFile  string `env:"TLS_KEY_FILE"`

	ForceSchemeHTTPS bool `env:"FORCE_SCHEME_HTTPS" envDefault:"true"`

	S3Endpoint  string `env:"S3_ENDPOINT,required"`
	S3AccessKey string `env:"S3_ACCESS_KEY"`
	S3SecretKey string `env:"S3_SECRET_KEY"`
	S3Bucket    string `env:"S3_BUCKET,required"`
	S3Region    string `env:"S3_REGION,required"`

	// MaxResponseBytes bounds the size of a served object body. 0 disables the limit.
	MaxResponseBytes int64 `env:"MAX_RESPONSE_BYTES" envDefault:"10485760"`

	// Verification knobs.

	ClockSkewSeconds int `env:"CLOCK_SKEW_SECONDS" envDefault:"60"`
	MinRSAKeyBits    int `env:"MIN_RSA_KEY_BITS" envDefault:"2048"`

	// Trusted signer public keys, keyed by CloudFront Key-Pair-Id.

	TrustedSigners TrustedSigners `env:"TRUSTED_SIGNERS"`
}

func Load() (Config, error) {
	_ = godotenv.Load()

	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse environment: %w", err)
	}

	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Config{}, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}

	for id, key := range cfg.TrustedSigners {
		if cfg.MinRSAKeyBits > 0 && key.N.BitLen() < cfg.MinRSAKeyBits {
			return Config{}, fmt.Errorf(
				"trusted signer %q: public key is %d bits, below minimum %d", id, key.N.BitLen(), cfg.MinRSAKeyBits,
			)
		}
	}

	return cfg, nil
}

func (c Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}
