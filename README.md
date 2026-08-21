# Garagefront

Cloudfront emulator for Garage/S3 and LibreChat enabling "cookies" image signing.

> ## ⚠️ TLS is expected to terminate at a reverse proxy
>
> This service is designed to sit **behind a reverse proxy** (Nginx, Caddy, NPM, etc.) that terminates TLS. Signed
> cookies are marked `Secure` + `SameSite=None`, which browsers will only transmit over HTTPS.
>
> If you expose this service over plain HTTP directly (i.e. reachable at `http://` from a browser), signed cookies
> will **not** work, and any traffic to it will be unencrypted. Ensure the proxy enforces HTTPS at the DNS/edge
> level and forwards requests to this service over a trusted internal network.
>
> You may need to adjust access lists, if applicable, such that both Librechat and trusted devices can access
> Garagefront-served assets.
>
> See `FORCE_SCHEME_HTTPS` below. With the default value (`true`) the service assumes requests arrived over HTTPS even
> though the proxy speaks plain HTTP.
>
> To verify cookie policies signed over `https://` URLs, the browser will only transmit cookies over HTTPS.

See [`docs/DIVERGENCES.md`](docs/DIVERGENCES.md) for more information.

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

The private key goes to LibreChat (`CLOUDFRONT_PRIVATE_KEY`); the public key is referenced here via `TRUSTED_SIGNERS`.
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
