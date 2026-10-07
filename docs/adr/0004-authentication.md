# ADR 0004 — Authentication & sessions

**Status:** accepted

* Passwords: Argon2id (argon2-cffi), min 12 chars, dummy-hash verification for unknown users (no timing oracle),
  uniform error for unknown user / wrong password / inactive account. Login is rate-limited per IP and per email.
* Access token: HS256 JWT, 15 min, `iss`/`aud`/`exp`/`iat`/`jti` required, `alg` pinned; held **in memory** by
  the SPA. Authorization data is not trusted from the token (ADR 0002).
* Refresh token: 384-bit opaque value in an `HttpOnly; SameSite=Strict; Path=/api/v1/auth` cookie (`Secure` in
  production); only its SHA-256 is stored. Single use with rotation; replay of a rotated token revokes the whole
  family. Refresh/logout/switch-tenant additionally require `X-Requested-With: threat-hunt` (CSRF guard).
* Deferred: asymmetric signing keys/rotation (needed once multiple services verify tokens), MFA/OIDC SSO, API keys
  for connectors (service accounts), password reset flow.
