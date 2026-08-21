# Divergences

> ...from a full CloudFront emulator.

TL;DR: In practice this means: if your workload is LibreChat serving inline images and avatars, Garagefront behaves
like CloudFront. If you rely on anything else CloudFront offers, it won't.

Garagefront is a purpose-built emulator for one specific workload: serving LibreChat inline images and avatars behind
signed cookies. It is not a general-purpose CloudFront replacement. The list below is not exhaustive, but covers the
differences most likely to matter to an end user.

## Will Not Implement

- Signed URLs and canned policies:
    - Only signed cookies with a custom policy (`CloudFront-Policy`) are verified.
    - Signed URL query parameters (`Policy`, `Signature`, `Key-Pair-Id`, `Expires`) and canned policies
      (`CloudFront-Expires`) are not supported, because LibreChat never uses them for images or avatars.
- `DateGreaterThan` and `IpAddress` conditions:
    - Cookie policies are only checked for expiry (`DateLessThan`) and resource matching.
    - Start-time and source-IP restrictions are ignored.
- Multi-statement policies; LibreChat always emits a single statement per cookie; only the first statement is honoured.
- Uploads, deletes, invalidation, and management APIs:
    - LibreChat writes directly to S3/Garage; Garagefront is read-only (`GetObject`/`HeadObject`).
    - `invalidateOnDelete` is assumed disabled.
- Origin Access Control and bucket-policy enforcement:
    - Garagefront uses its own S3-compatible credentials rather than AWS OAC.
- Caching, edge behaviours, and Lambda@Edge; there is no built-in CDN caching layer.
- ECDSA/other keys; only RSA public keys are accepted as trusted signers.

## Different Implementation

- Signature payload; verification is against the raw JSON policy string (as AWS signs it), not the base64-encoded
  cookie value.
- Base64 variant; CloudFront uses a non-standard base64 alphabet (`+` to `-`, `/` to `~`, `=` to `_`), which
  Garagefront decodes accordingly.
- Scheme detection; TLS is expected to terminate at a reverse proxy, so by default (`FORCE_SCHEME_HTTPS=true`)
  requests are treated as `https`.
- Clock skew; an optional tolerance (`CLOCK_SKEW_SECONDS`) accepts tokens that are past expiry by a small margin.

## Hardened

- Host validation; requests whose `Host` header does not match `PUBLIC_HOST` are rejected.
- Minimum signer key size; trusted keys shorter than `MIN_RSA_KEY_BITS` (default 2048) are rejected.
