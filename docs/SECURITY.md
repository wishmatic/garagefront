# Security

## Disclosure

- Responsible disclosure: do not publish, share, or discuss a suspected vulnerability before it is resolved.
    - Contact maintainers directly rather than filing a public report or mentioning it publicly.
- Include enough detail to reproduce the issue: affected version, environment, and a minimal reproduction if you can.

## Supported Versions

Only the latest release on the `main` branch receives security fixes. There are no long-term-support branches.

## Security Model

Garagefront is a read-only, self-hosted stand-in for CloudFront serving LibreChat inline images and avatars. The
following assumptions shape what is, and is not, considered a vulnerability:

- TLS is expected to terminate at a reverse proxy in front of Garagefront, not at Garagefront itself.
- Garagefront and its reverse proxy share a trusted private network.
- Garagefront is reachable only by the reverse proxy and trusted clients, not the public internet.
- Garagefront trusts its configured signer keys; possession of the private signing key is equivalent to full access.
- Objects are written by LibreChat directly to S3/Garage; Garagefront is read-only.

Reports that rely on violating these assumptions (for example, exposing Garagefront directly to the public internet
without TLS, or an already-compromised signer key) are out of scope.

## Accepted By Design

Future audits should not re-flag the items below.

- SHA-1 signature verification:
    - LibreChat signs CloudFront cookies with SHA-1 by default. It does not pass an `algorithm` to
      `@aws-sdk/cloudfront-signer`, so the cookies Garagefront must accept are SHA-1 signed.
    - SHA-1 is therefore the primary verification path, with SHA-256 retained as a fallback. This cannot be changed
      without breaking LibreChat compatibility, unfortunately.
- Plain HTTP between the reverse proxy and this service:
    - Garagefront is designed to sit behind a reverse proxy that terminates TLS. The proxy and Garagefront share a
      private network, so plain HTTP on that hop is the intended deployment and not a hardening gap.
- `FORCE_SCHEME_HTTPS=true` by default:
    - Because TLS terminates at the proxy, requests arrive as plain HTTP and would otherwise be misread as `http://`.
      Forcing `https` is required for cookie policies signed over `https://` URLs to verify correctly.
- `CLOCK_SKEW_SECONDS` tolerance:
    - A deliberate, configurable allowance for clock drift between the signer and this service.
- Long `Cache-Control` with `immutable` on served objects.

## Known Issues

- No rate limiting on the served endpoints:
    - Requests are verified before any upstream storage call, so unauthenticated traffic never reaches S3. However, a
      valid signed cookie is broadly scoped (`/i/*` or `/a/*`) and long-lived, so it can be replayed to drive a 1:1
      amplification of `GetObject` requests against the origin. There is no in-process cache so every cache-miss inline
      image load reaches the origin.
    - In the intended deployment this is mitigated by the reverse proxy's asset cache (Nginx Proxy Manager "Cache
      Assets"): responses carry `Cache-Control: public, max-age=31536000, immutable`, so repeated requests for the same
      object are served from the proxy cache and never reach the origin. That covers the dominant case (many clients
      loading the same stable-keyed images/avatars). It does not bound a determined actor enumerating _distinct_ keys
      (cache misses), nor raw request rate; for the self-hosted, trusted-client model this residual is not much of a
      risk. Still, it could still be something worth fixing in future.

## Agentic Audit

An agent should, on top of its usual thorough security review, provide potential mitigations, whether or not these
mitigations can be wholly performed by an agent, and regardless of if it can or not, the effort/size of the mitigation
suggested. Don't mention non-issues; focus on existing issues and their mitigations. At the bottom of the report,
indicate the strength of the code's security posture and what that strength would be with the mitigations in place.
