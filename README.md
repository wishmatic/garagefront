# garagefront

Cloudfront emulator for Garage and LibreChat enabling "cookies" image signing.

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

## Local Development

```sh
cp .env.example .env
go run ./cmd/server
go build ./...
go vet ./...
go test ./...
```
