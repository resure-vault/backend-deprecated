# SM Vault - Backend (TypeScript)

This repository contains a TypeScript (Express + Bun) rewrite of the original Go backend for SM Vault. It aims to preserve API shapes, email templates, and encryption behavior.

## Quick start

1. Copy `.env.example` to `.env` and fill required values (DATABASE_URL, DB_SCHEMA, JWT_SECRET, RESEND_API_KEY, RESEND_AUDIENCE_ID, REDIS_URL as needed).
2. Install dependencies: `bun install`
3. Run migrations: `bun run migrate:run`
4. Start dev server: `bun run dev`

## Development

- Type checking: `bun run check`
- Build: `bun run build`
- Run migrations: `bun run migrate:run`

## Contributing

See `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` for guidelines.
