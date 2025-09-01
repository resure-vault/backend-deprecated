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

// reset token service
// stores reset tokens in redis with a ttl and provides a memory fallback for dev
// tokens are temporary and single-use; production should not use the in-memory fallback

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
