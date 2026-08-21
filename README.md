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

### Clock skew

Signed cookies carry an absolute expiry. To tolerate a small difference between the clocks of LibreChat (the signer)
and this service, `CLOCK_SKEW_SECONDS` (default 60) accepts a token that is past its expiry by up to that many
seconds. This effectively extends cookie lifetime by that amount; set it to `0` if you want strict expiry.

### Scheme handling

`FORCE_SCHEME_HTTPS` (default `true`) makes the verifier treat every request as `https`, which is required when TLS
terminates at the reverse proxy. Set it to `false` only if TLS terminates at this service itself.

## Local Development

```sh
cp .env.example .env
go run ./cmd/server
go build ./...
go vet ./...
go test ./...
```
