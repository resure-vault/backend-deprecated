# API Endpoints

Base path: `/api/v1`

Overview of endpoints implemented in this repository (handlers found under `internal/handlers`).

---

## Auth

### POST /api/v1/auth/signup
- Description: Create a new user account.
- Auth: Public
- Body (application/json):
  - email (string, required, email format enforced by binding)
  - password (string, required, min 8)
  - master_password (string, required, min 8) — used for encrypting secrets
- Responses:
  - 201 Created: returns `LoginResponse` with `user` and `token`.
  - 400 Bad Request: validation failed or malformed JSON.
  - 409 Conflict: user already exists.
  - 500 Internal Server Error: server/db errors.
- Notes: Signup now uses a DB transaction and attempts to detect Postgres unique-violation errors (23505) to return 409.


### POST /api/v1/auth/login
- Description: Authenticate a user and return JWT.
- Auth: Public
- Body (application/json):
  - email (string, required)
  - password (string, required)
  - master_password (string, required)
- Responses:
  - 200 OK: returns `LoginResponse` with `user` and `token`.
  - 400 Bad Request: validation failed or malformed JSON.
  - 401 Unauthorized: invalid credentials or record not found.
  - 500 Internal Server Error: server/db errors.
- Notes: Login checks password and master password; records not found return 401.

---

## Secrets (JWT-protected or API-key protected)

All protected endpoints require the `middleware.AuthRequired` middleware which sets `user` in the context. API-key protected endpoints use `ValidateAPIKey` middleware which also sets `user`.

### GET /api/v1/secrets
- Description: List secrets for the authenticated user.
- Auth: JWT or API Key (see main router grouping)
- Query params:
  - page (int, default 1)
  - limit (int, default 50)
  - category (string, optional)
  - search (string, optional) — searches `name` and `description` (case-insensitive)
- Responses:
  - 200 OK: returns `secrets` array and `pagination` object.
  - 401 Unauthorized: if user not set by middleware.
  - 500 Internal Server Error: on DB errors.

### POST /api/v1/secrets
- Description: Create a new secret for the authenticated user.
- Auth: JWT (middleware.AuthRequired)
- Headers:
  - X-Master-Password (string, required) — used to encrypt secret value; must match the stored master password
- Body (application/json):
  - name (string, required)
  - value (string, required)
  - category (string, optional)
  - description (string, optional)
- Responses:
  - 201 Created: returns created secret with `value` masked as `[ENCRYPTED]`.
  - 400 Bad Request: validation failed or missing master password header.
  - 401 Unauthorized: invalid master password.
  - 409 Conflict: secret with same name exists for the user.
  - 500 Internal Server Error: on DB/encryption errors.

### PUT /api/v1/secrets/:id
- Description: Update a secret owned by the authenticated user.
- Auth: JWT
- Headers:
  - X-Master-Password (string, required when updating value)
- Body (application/json): same fields as create (name/value/category/description)
- Responses:
  - 200 OK: returns updated secret with `value` masked.
  - 400 Bad Request: validation errors.
  - 401 Unauthorized: invalid master password or user not set.
  - 404 Not Found: secret not found.
  - 409 Conflict: another secret with same name exists.
  - 500 Internal Server Error: on DB/encryption errors.

### DELETE /api/v1/secrets/:id
- Description: Delete a secret owned by the authenticated user.
- Auth: JWT
- Responses:
  - 200 OK: returns deleted secret id/name.
  - 401 Unauthorized: if user not set.
  - 404 Not Found: secret not found.
  - 500 Internal Server Error: DB error on delete.

### GET /api/v1/secrets/:id
- Description: Get and decrypt a secret value for the authenticated user.
- Auth: JWT
- Headers:
  - X-Master-Password (string, required) — used to decrypt
- Responses:
  - 200 OK: returns secret with decrypted `value`.
  - 400 Bad Request: missing master password header.
  - 401 Unauthorized: invalid master password.
  - 404 Not Found: secret not found.
  - 500 Internal Server Error: decryption/DB errors.

---

## API Keys (JWT-protected)

All routes require JWT auth (AuthRequired middleware) and operate on the authenticated user's API keys.

### GET /api/v1/apikeys
- Description: List user's API keys (cached in Redis).
- Auth: JWT
- Query params:
  - page (int, default 1)
  - limit (int, default 20)
  - status (string: "active"|"inactive")
- Responses:
  - 200 OK: returns `api_keys` with shorted key strings and pagination.
  - 401 Unauthorized: if user not set.

### POST /api/v1/apikeys
- Description: Create a new API key for the authenticated user. Shows full key only once.
- Auth: JWT
- Body (application/json):
  - name (string, required)
- Responses:
  - 201 Created: returns object with `api_key` (id, name, key, is_active, created_at).
  - 400 Bad Request: invalid name or limit reached (max 10 active keys).
  - 409 Conflict: name already exists for user.
  - 500 Internal Server Error: on DB errors.
- Notes: Key is stored as `svp_<hex...>` and cached validation entries are created in Redis.

### PUT /api/v1/apikeys/:id
- Description: Update API key name or toggle active state.
- Auth: JWT
- Body (application/json):
  - name (string, optional)
  - is_active (boolean, optional)
- Responses:
  - 200 OK: returns updated key (key value masked).
  - 400 Bad Request: invalid format.
  - 404 Not Found: key not found.
  - 409 Conflict: name exists.
  - 500 Internal Server Error: DB/cache errors.

### DELETE /api/v1/apikeys/:id
- Description: Permanently deletes an API key.
- Auth: JWT
- Responses:
  - 200 OK: returns deleted id/name.
  - 404 Not Found: key not found.
  - 500 Internal Server Error: DB/cache errors.

### POST /api/v1/apikeys/:id/revoke
- Description: (Implemented as `RevokeAPIKey` handler) Deactivate an API key.
- Auth: JWT
- Responses:
  - 200 OK: returns id/name of revoked key.
  - 404 Not Found: key not found.

### API key usage (ValidateAPIKey middleware)
- Header: `X-API-Key: svp_<hex...>` or Authorization: Bearer <key>
- Validation: checks Redis cached validity key first, falls back to DB lookup and caches result.
- Sets `user` and `api_key` in context on success.

---

## Health

### GET /health
- Description: Server health endpoint (cached for 30 seconds using Redis).
- Auth: Public
- Responses:
  - 200 OK: {"status":"ok"}

---

## Notes
- JWT generation and validation live in `internal/utils/jwt.go`.
- Database models in `internal/models` define request/response bindings.
- Middlewares are in `internal/middleware` and include AuthRequired, API key middleware, CORS, and logger.