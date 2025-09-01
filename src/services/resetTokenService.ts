import { createClient, RedisClientType } from 'redis'
import { config } from '../config'
import { randomUUID } from 'crypto'

let redisClient: RedisClientType | null = null
let usingRedis = false

async function initRedis() {
  if (!config.REDIS_URL) return
  if (redisClient) return
  redisClient = createClient({ url: config.REDIS_URL })
  try {
    await redisClient.connect()
    console.log('resetTokenService: connected to redis')
    usingRedis = true
  } catch (err) {
    console.warn('resetTokenService: failed to connect to redis, falling back to in-memory store', err)
    redisClient = null
    usingRedis = false
  }
}

const IN_MEMORY: Map<string, { userId: number; expiresAt: number }> = new Map()
const TTL_SECONDS = 60 * 60 // 1 hour

export async function createResetToken(userId: number) {
  await initRedis()
  const token = randomUUID()
  const expiresAt = Date.now() + TTL_SECONDS * 1000
  if (usingRedis && redisClient) {
    await redisClient.set(`reset:${token}`, String(userId), { EX: TTL_SECONDS })
  } else {
    IN_MEMORY.set(token, { userId, expiresAt })
  }
  return token
}

export async function getResetToken(token: string) {
  await initRedis()
  if (usingRedis && redisClient) {
    const v = await redisClient.get(`reset:${token}`)
    if (!v) return null
    return { userId: parseInt(v, 10), expiresAt: Date.now() + TTL_SECONDS * 1000 }
  }
  const rec = IN_MEMORY.get(token)
  if (!rec) return null
  if (rec.expiresAt < Date.now()) {
    IN_MEMORY.delete(token)
    return null
  }
  return rec
}

export async function deleteResetToken(token: string) {
  await initRedis()
  if (usingRedis && redisClient) {
    await redisClient.del(`reset:${token}`)
  } else {
    IN_MEMORY.delete(token)
  }
}

export function isUsingRedis() {
  return usingRedis
}
