/*
 * resure — the best way to store your secrets instead of forgetting them.
 *
 * Copyright (c) 2025-present
 * Shubham Yadav (bas3line), Nandha (almightynan)
 * License: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

// apikey service
// create and validate api keys; store hmac in db and return raw key at creation
// caches user mapping in redis when available
// remember: rotate HMAC_PEPPER carefully to avoid invalidating keys recklessly

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
