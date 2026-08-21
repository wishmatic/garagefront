# Garagefront

Cloudfront emulator for Garage/S3 and LibreChat enabling "cookies" image signing.

> Warning!

> This service is designed to sit behind a reverse proxy (Nginx, Caddy, NPM, etc.) that terminates TLS. Signed
> cookies are marked `Secure` + `SameSite=None`, which browsers will only transmit over HTTPS.
>
> If you expose this service over plain HTTP directly (i.e. reachable at `http://` from a browser), signed cookies
> will _not_ work, and any traffic to it will be unencrypted. Ensure the proxy enforces HTTPS at the DNS/edge
> level and forwards requests to this service over a trusted internal network.
>
> You may need to adjust access lists, if applicable, such that both Librechat and trusted devices can access
> Garagefront-served assets.
>
> See `FORCE_SCHEME_HTTPS` below. With the default value (`true`) the service assumes requests arrived over HTTPS even
> though the proxy speaks plain HTTP.
>
> To verify cookie policies signed over `https://` URLs, the browser will only transmit cookies over HTTPS.

## What It Does

Garagefront is a read-only stand-in for CloudFront. It serves two kinds of object, fetched from S3/Garage with
SigV4-signed `GetObject` requests, and only after verifying a CloudFront signed cookie:

- `/i/...` private images, scoped to a user
- `/a/...` avatars, scoped to a tenant

The object key equals the request path (the leading `i`/`a` segment is part of the key), so `/i/images/user/file.png`
fetches the S3 object `i/images/user/file.png`. Region-aware paths (`/i/r/<region>/...`) work when LibreChat is
configured with `includeRegionInPath`.

Responses echo the object's `Content-Type`, `Content-Length`, `ETag`, and `Last-Modified`, plus a long
`Cache-Control: public, max-age=31536000, immutable`.

## LibreChat Configuration

Point LibreChat at Garagefront with `fileStrategies` and a `cloudfront` block in `librechat.yaml`:

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
parent of that host so the browser sends the signed cookies (see the TLS note above).

The CloudFront key pair is split across the two sides: the private key and key-pair ID go to LibreChat via the
`CLOUDFRONT_KEY_PAIR_ID` and `CLOUDFRONT_PRIVATE_KEY` environment variables, and the public key plus the same
key-pair ID go to Garagefront via `TRUSTED_SIGNERS` (below).

### Why Only Images

Only `image` and `avatar` point at `cloudfront`. The rest stay on `s3` (or `local`) because they don't need signed
cookies: docs are downloaded on demand, so LibreChat can mint a short-lived presigned URL when you click download.
Images and avatars are loaded inline on every page, so they need a long-lived cookie instead.

Of course, you can always just use local storage for everything or deal with the occasional broken image.

## Deployment

Deploy as a Docker container. You will need to specify the envars present in the `.env.example` file.

### Trusted Signers

`TRUSTED_SIGNERS` is a comma-separated list of `keypairid=/path/to/public.pem` entries. Public keys may be PKIX
(`BEGIN PUBLIC KEY`) or PKCS#1(`BEGIN RSA PUBLIC KEY`) PEM.

Generate the key pair on Linux with:

```sh
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

Signer keys shorter than `MIN_RSA_KEY_BITS` (default 2048) are rejected.

### Algorithm

LibreChat signs CloudFront cookies with **SHA-1** by default (it does not pass an `algorithm` to
`@aws-sdk/cloudfront-signer`). This service therefore verifies SHA-1 signatures, with SHA-256 accepted as a fallback
for forward compatibility.

### Divergences

This is an emulator, not a full CloudFront replacement. See [`docs/DIVERGENCES.md`](docs/DIVERGENCES.md) for the
differences you should be aware of before deploying.

### Clock Skew

Signed cookies carry an absolute expiry. To tolerate a small difference between the clocks of LibreChat (the signer)
and this service, `CLOCK_SKEW_SECONDS` (default 60) accepts a token that is past its expiry by up to that many
seconds. This effectively extends cookie lifetime by that amount; set it to `0` if you want strict expiry.

### Scheme Handling

`FORCE_SCHEME_HTTPS` (default `true`) makes the verifier treat every request as `https`, which is required when TLS
terminates at the reverse proxy. Set it to `false` only if TLS terminates at this service itself.

### TLS

This service can serve HTTPS directly when both `TLS_CERT_FILE` and `TLS_KEY_FILE` are set; otherwise it listens on
plain HTTP and expects a reverse proxy to terminate TLS. When running behind a proxy, keep `FORCE_SCHEME_HTTPS=true` so
cookies signed over `https://` URLs verify correctly.

In the intended deployment the reverse proxy and Garagefront share a private network, so plain HTTP between them is
fine and is the default; the proxy is the security boundary and the only hop a browser ever sees. The TLS options above
are primarily for standalone or local testing rather than a hardening step.

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

`go test ./...` runs unit tests plus the end-to-end integration test in `internal/integration`. The integration test
serves an object from an in-process mock Garage and verifies a real signed cookie minted by
`@aws-sdk/cloudfront-signer` (the same library LibreChat uses), so it exercises the full verify path with no external
services.

The signed-cookie fixture and throwaway RSA key pair are generated on demand (and in CI) rather than committed, since
the cookie signature is derived from the private key. They live under `data/tests/`, which is gitignored.

To generate them locally:

```sh
sh scripts/integration/generate-fixtures.sh
```

This creates the key pair with `openssl`, installs the TypeScript signer with pnpm, and mints a cookie with a
far-future expiry. To run the signer directly instead:

```sh
cd scripts/integration
pnpm install
pnpm sign ../../data/tests/test_private.pem APKA1234 "https://cdn.example.com/i/*" \
  --epoch 4102444800 > ../../data/tests/cookies.json
```
