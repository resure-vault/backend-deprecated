import AppDataSource from '../data-source'
import { APIKey, User } from '../entities/Entities'
import { hashAPIKey, generateRawAPIKey } from '../utils/crypto'
import { config } from '../config'
import { createClient } from 'redis'

const redisClient = createClient({ url: config.REDIS_URL || undefined })
redisClient.connect().catch(() => {})

export async function createAPIKeyForUser(user: User, name: string) {
  const repo = AppDataSource.getRepository(APIKey)
  const raw = generateRawAPIKey()
  const hashed = hashAPIKey(raw, config.HMAC_PEPPER)
  const k = repo.create({ userId: user.id, name, key: hashed, isActive: true })
  await repo.save(k)
  // cache mapping
  if (config.REDIS_URL) {
    await redisClient.set(`kv:${hashed}`, String(user.id), { EX: 3600 })
  }
  return { id: k.id, name: k.name, key: raw, created_at: k.createdAt }
}

export async function validateAPIKey(raw: string) {
  if (!raw || !raw.startsWith('svp_') || raw.length != 68) return null
  const hashed = hashAPIKey(raw, config.HMAC_PEPPER)
  // check redis
  if (config.REDIS_URL) {
    const v = await redisClient.get(`kv:${hashed}`)
    if (v) {
      const uid = parseInt(v, 10)
      const userRepo = AppDataSource.getRepository(User)
      return await userRepo.findOneBy({ id: uid })
    }
  }
  // fallback to DB
  const repo = AppDataSource.getRepository(APIKey)
  const rec = await repo.findOne({ where: { key: hashed, isActive: true } })
  if (!rec) return null
  const userRepo = AppDataSource.getRepository(User)
  return await userRepo.findOneBy({ id: rec.userId })
}
