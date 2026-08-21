# CloudFront Emulator — Build Spec

A self-hosted CloudFront stand-in in **Go** that serves LibreChat images/avatars from **Garage** (S3-compatible) and enforces CloudFront signed cookies.

## LibreChat config it serves

```yaml
fileStrategies:
    default: s3
    avatar: cloudfront
    image: cloudfront
    document: s3
    skills: s3

cloudfront:
    domain: "<snip>"
    imageSigning: cookies
    cookieDomain: "<snip>"
    cookieExpiry: 1800
    urlExpiry: 3600
    requireSignedAccess: true
    invalidateOnDelete: false
```

## Responsibilities (must do)

**1. Serve objects from Garage**

- Map request path → object key (`/i/...`, `/a/...`).
- SigV4-signed `GetObject` / `HeadObject` against the S3-compatible endpoint.
- Return bytes with Garage's `Content-Type`, `Content-Length`, `ETag`, `Last-Modified`.
- Map errors: `NoSuchKey` → 404, `AccessDenied` → 403.

**2. Verify CloudFront signed cookies**

- Read `CloudFront-Key-Pair-Id`, `CloudFront-Signature`, and one of `CloudFront-Expires` (canned) or `CloudFront-Policy` (custom).
- Look up the trusted public key by `CloudFront-Key-Pair-Id`.
- Verify the RSA signature over the exact policy payload.
- Check expiry (`DateLessThan` / `Expires` > now, with clock-skew tolerance).
- Match the policy `Resource` against the request URL.
- Reject with **403** (`Missing Key-Pair-Id` / `Access Denied`) on any failure.

**3. Serve HTTPS on the exact hostname**

- TLS on the host matching `cloudfront.domain`, under `cookieDomain` (e.g. `cdn.example.com` under `.example.com`).
- Cookies are `Secure` + `SameSite=None`; plain HTTP won't work in browsers.

## Out of scope (must not do)

- **Uploads** — LibreChat writes straight to Garage.
- **Signed URL verification** — documents/skills use `s3` and never hit this.
- **Invalidation / management API** — `invalidateOnDelete: false`.
- **OAC / bucket-policy enforcement** — uses its own Garage creds.
- **Caching** — optional, not required for correctness.
- **Lambda@Edge**.

## Signed-cookie verification details

**Cookie fields**

| Cookie                   | Meaning                                     |
| ------------------------ | ------------------------------------------- |
| `CloudFront-Key-Pair-Id` | Which public key to use                     |
| `CloudFront-Signature`   | Base64 RSA signature over the policy string |
| `CloudFront-Expires`     | Unix expiry — canned policy                 |
| `CloudFront-Policy`      | Base64-encoded policy JSON — custom policy  |

**Policy handling**

- **Custom** (expected case — LibreChat scopes cookies to paths): the signed payload is the literal `CloudFront-Policy` value. Decode to get `Statement[].Resource` + `Condition.DateLessThan.AWS:EpochTime`. Verify the signature over the raw value as-is — no JSON reconstruction.
- **Canned** (only for per-URL cookies): reconstruct the canonical policy JSON from the request URL + `CloudFront-Expires`, byte-exact.

**Signature**

- RSA, PKCS#1 v1.5 — verify with **both SHA-1 and SHA-256** (`rsa.VerifyPKCS1v15`).

**Resource matching**

- Custom `Resource` may contain wildcards: `https://cdn.example.com/i/*`.
- Match: scheme exact, host exact, path globbed. Request `Host` header + path must satisfy the `Resource`.

**Edge cases**

- Base64 variants (`+`/`/`/`=` vs `-`/`_`, padding).
- Clock skew between LibreChat and this service.
- URL/path encoding vs the raw path used in the signed Resource.
- Missing/empty cookies, wrong key-pair ID, expired timestamp.

## Paths served

- `/i/...` — private images, scoped to user.
- `/a/...` — avatars, scoped to tenant.
- Region-aware variants only if `includeRegionInPath`: `/i/r/<region>/...`, `/a/r/<region>/...`.

## Configuration it needs

| Setting                                                | Source                              |
| ------------------------------------------------------ | ----------------------------------- |
| Public host                                            | Must equal `cloudfront.domain` host |
| Garage endpoint + read-only access key/secret + bucket | Its own S3-compatible creds         |
| Trusted signer list                                    | Public key + key-pair ID            |

**Key pair setup**

- Generate one CloudFront RSA key pair (public + private).
- **Private key** → LibreChat env: `CLOUDFRONT_KEY_PAIR_ID`, `CLOUDFRONT_PRIVATE_KEY` (PEM).
- **Public key + key-pair ID** → this service's trusted signer list.

## Response headers

- Required: correct `Content-Type`, `Content-Length`, `ETag`, `Last-Modified`.
- Optional: long `Cache-Control` (`public, max-age=31536000, immutable`) for cacheable paths.
- Optional CloudFront-ish headers (`X-Cache`, `Via`, `X-Amz-Cf-Id`).

## Acceptance criteria

- Go HTTP service serves `/i/*` and `/a/*` keys from Garage with correct content-type.
- Verifies signed cookies and returns 403 on missing/invalid/expired signature.
- Wildcard `Resource` matching works.
- Round-trips a real signed cookie minted by `@aws-sdk/cloudfront-signer`.
- Served over HTTPS on the configured domain.

## Test approach

- Mint a real signed cookie with a small `@aws-sdk/cloudfront-signer` script (the signer LibreChat uses), iterate until the Go verifier accepts it.

## Optional future (only if documents/skills later route through it)

- Signed URL verification (`Expires`/`Signature`/`Key-Pair-Id` query params, plus custom `Policy`).
- `Range` / `If-None-Match` passthrough for resumable downloads.

## References

- https://www.librechat.ai/docs/configuration/cdn/cloudfront
- https://github.com/mackee/localfront
- `@aws-sdk/cloudfront-signer`
