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
// this module stores reset tokens in redis with a ttl. the previous in-memory fallback
// was removed so that tokens are reliably shared across instances.
// note: initRedis will throw if REDIS_URL is not configured. configure your env.

import { createClient, RedisClientType } from 'redis'
import { config } from '../config'
import { randomUUID } from 'crypto'

let redisClient: RedisClientType | null = null
const TTL_SECONDS = 60 * 60 // 1 hour

async function initRedis() {
  if (redisClient) return
  if (!config.REDIS_URL || config.REDIS_URL.trim() === '') {
    throw new Error('REDIS_URL is required for reset token storage. set REDIS_URL in your environment')
  }
  redisClient = createClient({ url: config.REDIS_URL })
  try {
    await redisClient.connect()
    console.log('resetTokenService: connected to redis')
  } catch (err) {
    redisClient = null
    console.error('resetTokenService: failed to connect to redis', err)
    throw err
  }
}

export async function createResetToken(userId: number) {
  await initRedis()
  const token = randomUUID()
  // store userId under key with an expiry
  await redisClient!.set(`reset:${token}`, String(userId), { EX: TTL_SECONDS })
  return token
}

export async function getResetToken(token: string) {
  await initRedis()
  const key = `reset:${token}`
  const v = await redisClient!.get(key)
  if (!v) return null
  // compute expiresAt from remaining ttl (pttl returns ms)
  const pttl = await redisClient!.pTTL(key)
  const expiresAt = Date.now() + (pttl > 0 ? pttl : 0)
  return { userId: parseInt(v, 10), expiresAt }
}

export async function deleteResetToken(token: string) {
  await initRedis()
  await redisClient!.del(`reset:${token}`)
}

export function isUsingRedis() {
  return redisClient !== null
}
