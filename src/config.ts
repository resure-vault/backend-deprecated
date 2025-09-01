import dotenv from 'dotenv'
import path from 'path'

// load .env from the current project directory (backend-ts)
dotenv.config({ path: path.resolve(process.cwd(), '.env') })

function buildDatabaseURL() {
  if (process.env.DATABASE_URL && process.env.DATABASE_URL.trim() !== '') {
    return process.env.DATABASE_URL
  }
  const host = process.env.PROD_DB_HOST || process.env.DB_HOST || 'localhost'
  const port = process.env.PROD_DB_PORT || process.env.DB_PORT || '5432'
  const name = process.env.PROD_DB_NAME || process.env.DB_NAME || 'postgres'
  const user = process.env.PROD_DB_USER || process.env.DB_USER || 'postgres'
  const pass = process.env.PROD_DB_PASSWORD || process.env.DB_PASSWORD || ''
  // postgres connection string (without schema query param)
  if (pass) {
    return `postgres://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${host}:${port}/${name}`
  }
  return `postgres://${encodeURIComponent(user)}@${host}:${port}/${name}`
}

export const config = {
  PORT: process.env.PORT || '8080',
  DATABASE_URL: buildDatabaseURL(),
  DB_SCHEMA: process.env.PROD_DB_SCHEMA || process.env.DB_SCHEMA || 'public',
  REDIS_URL: process.env.REDIS_URL || '',
  JWT_SECRET: process.env.JWT_SECRET || 'change-me',
  HMAC_PEPPER: process.env.HMAC_PEPPER || 'pepper',
  RESEND_API_KEY: process.env.RESEND_API_KEY || '',
  RESEND_AUDIENCE_ID: process.env.RESEND_AUDIENCE_ID || ''
}

// Startup validation: in production, ensure critical secrets are not default placeholders
if ((process.env.NODE_ENV === 'production') && (config.JWT_SECRET === 'change-me' || config.HMAC_PEPPER === 'pepper')) {
  throw new Error('Critical secrets JWT_SECRET and HMAC_PEPPER must be set in production')
}
