# SECURITY.md

This document is an audit-style security summary for this repository. It is specific to the codebase (file and symbol references include paths in the repo).

1) Vulnerability reporting
- Contact: hi@yssh.dev [or] almightynan@gmail.com.
- Required report contents: affected component (file path and function), environment (DB_SCHEMA, DATABASE_URL), exact API call or PoC (curl/JSON), sample logs, impact estimate, and contact details. PGP-encrypt sensitive attachments if needed.
- Timeline expectations:
  - Acknowledgement: within 48 hours.
  - Initial triage & mitigation plan: within 10 business days.
  - Patch/coordinated disclosure: critical → emergency (1–7 days), high → expedited (7–30 days), medium/low → next release cycle.
- Safe-harbor: follow responsible disclosure, avoid destructive testing on production systems. Coordinate with the security contact.

2) Threat model — assets, adversaries, entry vectors (concrete)
- Assets
  - User secrets: `secrets.value` persisted via `src/entities/Entities.ts` (Secret entity)
  - User credentials: `users.password`, `users.master_password_hash` (User entity, `src/entities/Entities.ts`).
  - API keys: `api_keys.key` (APIKey entity, `src/entities/Entities.ts`).
  - Tokens: JWTs issued in `src/controllers/auth.ts`; reset tokens stored by `src/services/resetTokenService.ts`.
  - Third‑party secrets: `RESEND_API_KEY` in `src/config.ts` and `.env.example`.
  - Infrastructure credentials: DATABASE_URL, REDIS_URL, JWT_SECRET, HMAC_PEPPER in `src/config.ts` and `.env` files.
- Adversaries
  - Remote unauthenticated attackers probing `/api/v1/*` endpoints.
  - Authenticated attacker abusing authorized endpoints (listing/exfiltrating secrets).
  - Malicious insider with repo or infra access.
  - Supply-chain compromise via npm packages (`package.json` dependencies e.g., `argon2`, `@stablelib/xchacha20poly1305`, `resend`, `typeorm`).
- Entry vectors (concrete code locations)
  - HTTP endpoints: routers in `src/routes/*` and controllers in `src/controllers/*` (`auth`, `secrets`, `apikeys`).
  - Crypto operations: `src/utils/crypto.ts` (Encrypt/Decrypt, hashPassword, hashAPIKey).
  - Secret storage: `src/services/secretService.ts` (encryption/decryption flows).
  - Token persistence: `src/services/resetTokenService.ts` (Redis-backed with in-memory fallback).
  - DB migration and schema: `migrations/1693564800000-CreateInitialTables.ts` and `src/entities/Entities.ts`.
  - Email sending & audience: `src/utils/mail.ts` using `resend` SDK and templates under `/templates`.

3) Cryptographic design (what the code implements - parameters and formats)
- Password hashing
  - Implementation: `src/utils/crypto.ts` uses the `argon2` package (argon2id).
  - Parameters: timeCost = 3; memoryCost = 65536 (KB); parallelism = CPU count (dynamic); hashLength = 32.
  - Storage: argon2 PHC string returned by `argon2.hash()` stored in `users.password` and `users.master_password_hash`.
- Secrets encryption
  - Implementation: per-secret Argon2id key derivation followed by XChaCha20-Poly1305 AEAD via `@stablelib/xchacha20poly1305` in `src/utils/crypto.ts`.
  - Parameters: salt length = 16 bytes; nonce length = 24 bytes; Argon2id params as above; key length = 32 bytes.
  - Ciphertext format: `v1$<salt_b64>$<nonce_b64>$<ct_b64>` (produced and parsed by `Encrypt` and `Decrypt`).
  - Note: AEAD tag is included in the ciphertext output of the `seal()` call.
- API keys
  - Implementation: `hashAPIKey` in `src/utils/crypto.ts` uses HMAC-SHA256 with `config.HMAC_PEPPER`.
  - Raw keys: generated with `generateRawAPIKey()` (prefix `svp_` + 32 random bytes hex) and only the HMAC digest is stored in DB (`api_keys.key`).
- Reset tokens
  - Implementation: `src/services/resetTokenService.ts` stores UUID tokens in Redis under `reset:<token>` with TTL = 3600s (1 hour). In-memory fallback exists when `REDIS_URL` is not configured.

4) Operational hardening - concrete recommendations
- Environment & secrets
  - Require `JWT_SECRET` and `HMAC_PEPPER` be set in production (fail fast). Ensure `DATABASE_URL` and `REDIS_URL` are configured in production.
  - Use KMS/HSM (AWS KMS, GCP KMS, HashiCorp Vault) for production secrets; do not store real secrets in repo or `.env` files.
- Runtime
  - Enforce TLS for Postgres and Redis connections.
  - In production, require Redis and remove in-memory reset-token fallback; if Redis is missing, fail startup.
  - Use a distributed rate limiter (e.g., `express-rate-limit` with Redis store) instead of the current in-memory `src/middleware/rateLimit.ts`.
- CI/CD and dependency hygiene
  - Add `npm audit` / `bun` audit and Snyk/Dependabot in CI; fail builds on critical/high findings.
  - Pin dependency versions and commit lockfile (`bun.lock` / `package-lock.json`) for reproducible builds.
  - Replace fragile `ts-node/esm` dynamic imports for TypeORM CLI with a compiled JS bootstrap for migrations in CI.
- Monitoring & logging
  - Centralized structured logging; redact secrets before logging. Remove or sanitize statements like `console.error('welcome email failed:', err)` in `src/controllers/auth.ts`.
  - Alert on decryption failures, unexpected rate-limit spikes, and large data exports.
- Testing
  - Add unit/integration tests for crypto round-trip and cross-language compatibility with Go ciphertexts.

5) Breach response (operational playbook)
- Detection: collect logs (app, DB, Redis), enable audit logging on DB, and capture network traces if feasible.
- Containment: rotate `JWT_SECRET`, `HMAC_PEPPER`, and third-party keys (`RESEND_API_KEY`), invalidate active sessions, revoke API keys (`api_keys.is_active=false`).
- Eradication: patch vulnerable components or replace compromised packages, rebuild and redeploy images.
- Recovery: restore from known-good backups, re-seed minimal state if required, reissue credentials.
- Notification: follow applicable legal/regulatory timelines; inform affected users and publish incident details after containment.

6) Security gaps and TODOs (explicit code-level items)
- Legacy secret compatibility: no migration utility to rewrap legacy AES-encrypted secrets. If DB contains legacy AES records they are likely unreadable. Review `src/services/secretService.ts`.
- Redis fallback in production: `src/services/resetTokenService.ts` falls back to in-memory storage; unsafe for multi-instance deployments.
- Rate limiter: `src/middleware/rateLimit.ts` is in-memory and unsuitable for production; replace with Redis-backed rate limiter.
- Tooling fragility: `src/data-source.ts` uses dynamic top-level imports for ESM support; this can break CI/tooling. Provide a compiled bootstrap for TypeORM CLI.
- Sensitive logging: remove or sanitize logs that may include secrets (e.g., `console.error` calls in `src/controllers/auth.ts`, `src/index.ts`).
- Health endpoint exposure: `/health` (`src/index.ts`) returns DB/Redis booleans — restrict access in production.
- Dependency audit missing in CI: `.github/workflows/ci.yml` lacks `npm audit`/Snyk checks.
- Missing tests: no unit/integration tests covering cryptography and migration paths.

7) Remediation checklist (priority-ordered)
1. Enforce production env validation for JWT_SECRET, HMAC_PEPPER, DATABASE_URL, REDIS_URL; fail startup if missing.
2. Require Redis in production and remove in-memory reset token fallback.
3. Add dependency audit step in CI and enable automatic dependency alerts (Dependabot/Snyk).
4. Add unit tests for crypto round-trip and cross-language compatibility. Add CI test step.
5. Implement legacy AES→v1 rewrap utility for secrets migration.
6. Replace in-memory rate limiter with `express-rate-limit` + Redis store.
7. Harden logging and restrict `/health` output in production.
8. Provide compiled JS DataSource bootstrap for TypeORM CLI in CI.
9. Schedule third-party penetration testing and store redacted reports in `AUDIT_REPORTS/`.

8) Code reference map (quick)
- Crypto: `src/utils/crypto.ts` (Encrypt, Decrypt, hashPassword, hashAPIKey).
- Secret service: `src/services/secretService.ts`.
- Reset tokens: `src/services/resetTokenService.ts` (Redis + fallback).
- API keys: `src/services/apikeyService.ts`.
- Auth flows: `src/controllers/auth.ts`.
- Mail: `src/utils/mail.ts` and `/templates`.
- Config: `src/config.ts` and `.env.example`.

9) Immediate recommended actions
- Fail startup in production when critical secrets or REDIS_URL are missing.
- Add dependency audit in CI and enable Dependabot.
- Add crypto tests and legacy rewrap tooling.

Contact
- Send vulnerability reports to hi@yssh.dev [or] almightynan@gmail.com.

This document is produced as a code-centric security audit and is specific to the current repository state. 