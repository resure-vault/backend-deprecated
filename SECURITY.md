# Security

Recommendations:

- Set strong values for JWT_SECRET and HMAC_PEPPER in production.
- Use REDIS_URL in production; do not rely on in-memory reset tokens in multi-instance setups.
- Monitor dependencies for vulnerabilities and configure Dependabot / Snyk.
- Run periodic audits.
