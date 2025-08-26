# sm-backend

Backend service for storing and serving secrets (Gin + GORM + Redis).

## Prerequisites

- Go 1.24+
- PostgreSQL database
- Redis

## Environment

Copy the example env and fill values:

```bash
cp .env.example .env
# Edit .env and set your DB and JWT_SECRET values
```

## Build & Run

From the project root:

1. Download dependencies:

```bash
go mod download
```

2. Build the binary:

```bash
go build -o bin/server ./cmd/server
```

3. Run the server:

```bash
./bin/server
```

Alternatively run without building:

```bash
go run ./cmd/server/main.go
```

## Development

- To enable Gin debug mode set `GIN_MODE=debug` in your environment (or `.env`).
- Health check: `GET /health` (cached for 30s).
- API base: `/api/v1`
  - Auth: `/api/v1/auth/signup`, `/api/v1/auth/login`
  - Protected (JWT): `/api/v1/secrets`, `/api/v1/apikeys` (see routes in `cmd/server/main.go`)
  - API key protected: `GET /api/v1/secrets` (for API-key clients)