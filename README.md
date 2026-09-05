# Garagefront

Cloudfront emulator for Garage/S3 and LibreChat enabling "cookies" image signing.

## Quick Start

Run as a Docker container:

```sh
docker run -d \
  -e PUBLIC_HOST=https://librechat.example.com \
  -e S3_ENDPOINT=http://garage:3900 \
  -e S3_ACCESS_KEY=access-key \
  -e S3_SECRET_KEY=secret-key \
  -e S3_BUCKET=librechat-s3 \
  -e S3_REGION=garage \
  -e "TRUSTED_SIGNERS=APKA12345=/keys/public.pem" \
  -v /mnt/user/appdata/garagefront/keys:/keys/ \
  ghcr.io/wishmatic/garagefront:latest
```

## Why?

If you use LibreChat with Garage/some other S3-compatible backend, avatars and uploaded images will get you presigned
URLs which can expire after at most 7 days. This is "fine" for most cases, but the correct _usual_ way to handle this
is S3 + CloudFront.

This also gets you the benefit of image signing via cookies, so images can only be viewed from the same domain.

There aren't any tools that specifically do this for non-S3 S3-compatible backends that I could find, so this exists
to bridge that gap in a secure way on a local network.

This service exists so those images do not get stale specifically for LibreChat.

### Okay, but do I really need this?

Not really. This is a niche use case. You can just serve from local and that will work just as well. However, you
can't get cookie-based image signing with a local backend.

## What is it?

Garagefront is a read-only stand-in for CloudFront. It serves:

- `/i/...` private images, scoped to a user
- `/a/...` avatars, scoped to a tenant

E.g., `/i/images/user/file.png` fetches the S3 object `i/images/user/file.png`. Region-aware paths
(i.e., `/i/r/<region>/...`) work when LibreChat is configured with `includeRegionInPath`.

Note: Responses have a long `Cache-Control` header (`public, max-age=31536000, immutable`).

## LibreChat Configuration

In your Librechat configuration YAML:

```yaml
fileStrategies:
    default: s3
    avatar: cloudfront
    image: cloudfront
    document: s3
    skills: s3

cloudfront:
    domain: "https://cdn.example.com"
    imageSigning: cookies
    cookieDomain: ".example.com"
    cookieExpiry: 1800
    urlExpiry: 3600
    requireSignedAccess: true
    invalidateOnDelete: false
```

`cloudfront.domain` must be the public host Garagefront serves (its `PUBLIC_HOST`), and `cookieDomain` must be a
parent of that host.

The private key and key-pair ID go to LibreChat via the `CLOUDFRONT_KEY_PAIR_ID` and `CLOUDFRONT_PRIVATE_KEY` envars,
and the public key plus the same key-pair ID go to Garagefront via `TRUSTED_SIGNERS`.

## TLS Warning

This service is designed to sit behind a reverse proxy (Nginx, Caddy, NPM, etc.) that terminates TLS. Signed
cookies are marked `Secure` + `SameSite=None`, which browsers will only transmit over HTTPS.

See `FORCE_SCHEME_HTTPS` below. With the default value (`true`) the service assumes requests arrived over HTTPS even
though the proxy speaks plain HTTP.

To verify cookie policies signed over `https://` URLs, the browser will only transmit cookies over HTTPS.

See [TLS](#tls) below for more details.

## Information

### Trusted Signers

`TRUSTED_SIGNERS` is a comma-separated list of `keypairid=/path/to/public.pem` entries. Public keys may be PKIX
(`BEGIN PUBLIC KEY`) or PKCS#1(`BEGIN RSA PUBLIC KEY`) PEM.

Generate the key pair with:

```sh
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

Signer keys shorter than `MIN_RSA_KEY_BITS` (default 2048) are rejected.

### Algorithm

LibreChat signs CloudFront cookies with SHA-1 by default. This service therefore verifies SHA-1 signatures, with
SHA-256 accepted as a fallback for forward compatibility.

### Divergences

This is an emulator, not a full CloudFront replacement. See [`docs/DIVERGENCES.md`](docs/DIVERGENCES.md).

### TLS

This service can serve HTTPS directly when both `TLS_CERT_FILE` and `TLS_KEY_FILE` are set; otherwise it listens on
plain HTTP and expects a reverse proxy to terminate TLS. When running behind a proxy, keep `FORCE_SCHEME_HTTPS=true` so
cookies signed over `https://` URLs verify correctly.

In the intended deployment the reverse proxy and Garagefront share a private network. These TLS options are primarily
for standalone or local testing rather than a hardening step.

Generate a self-signed certificate for local testing with:

```sh
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=cdn.example.com"
```

## Local Development

```sh
cp .env.example .env
go run ./cmd/server
go build ./...
go vet ./...
go test ./...
```

## Tests

`go test ./...` runs unit tests plus the E2E test in `internal/integration`. The integration test serves an object
from an in-process mock Garage and verifies a real signed cookie minted by `@aws-sdk/cloudfront-signer`, the same
lib LibreChat uses as of writing, so it exercises the full verify path with no external services.

To generate fixtures locally:

```sh
sh scripts/integration/generate-fixtures.sh
```

To run the signer directly:

```sh
cd scripts/integration
pnpm install
pnpm sign ../../data/tests/test_private.pem APKA1234 "https://cdn.example.com/i/*" \
  --epoch 4102444800 > ../../data/tests/cookies.json
```
