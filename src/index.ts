import 'reflect-metadata'
import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import morgan from 'morgan'
import { config } from './config'
import AppDataSource from './data-source'

import authRouter from './routes/auth'
import secretsRouter from './routes/secrets'
import apikeysRouter from './routes/apikeys'

async function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

async function main() {
  // log database URL for debugging
  try {
    console.log('DATABASE_URL=', config.DATABASE_URL)
    const parsed = new URL(config.DATABASE_URL)
    console.log('DB host:', parsed.hostname, 'port:', parsed.port || 'default')
  } catch (err) {
    console.warn('Failed to parse DATABASE_URL for debug:', err)
  }

  // initialize TypeORM DataSource with retry/backoff
  const maxAttempts = 5
  let attempt = 0
  for (; attempt < maxAttempts; attempt++) {
    try {
      await AppDataSource.initialize()
      console.log('Database connected')
      break
    } catch (err: any) {
      console.error(`Database connection attempt ${attempt + 1} failed:`, err && err.message ? err.message : err)
      if (attempt < maxAttempts - 1) {
        const wait = (attempt + 1) * 2000
        console.log(`Retrying in ${wait}ms...`)
        await sleep(wait)
        continue
      }
      throw err
    }
  }

  // Verify the configured DB schema exists. Fail fast with a clear message if it does not.
  try {
    const schema = config.DB_SCHEMA || 'public'
    const r: any = await AppDataSource.query(`SELECT schema_name FROM information_schema.schemata WHERE schema_name = $1`, [schema])
    if (!r || r.length === 0) {
      throw new Error(`Database schema "${schema}" does not exist. Run the migrations (npm run migrate:run) or create the schema in your database.`)
    }
  } catch (err) {
    console.error('Schema check failed:', err)
    throw err
  }

  const app = express()
  app.use(helmet())
  app.use(cors())
  app.use(express.json())
  app.use(morgan('dev'))

  app.use('/api/v1/auth', authRouter)
  app.use('/api/v1/secrets', secretsRouter)
  app.use('/api/v1/apikeys', apikeysRouter)

  // health endpoint
  app.get('/health', async (req, res) => {
    try {
      const dbOk = !!AppDataSource.isInitialized
      let redisOk = false
      try {
        const { isUsingRedis } = await import('./services/resetTokenService')
        redisOk = isUsingRedis()
      } catch (err) {
        redisOk = false
      }
      return res.json({ status: 'ok', db: dbOk, redis: redisOk, time: new Date().toISOString() })
    } catch (err) {
      return res.status(500).json({ status: 'error', error: String(err) })
    }
  })

  const port = parseInt(String(config.PORT), 10) || 8080
  app.listen(port, () => console.log(`Server running on ${port}`))
}

main().catch(err => {
  console.error('Fatal startup error:', err)
  process.exit(1)
})
