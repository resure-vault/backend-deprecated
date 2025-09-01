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

import { Request, Response, NextFunction } from 'express'

const BUCKETS: Map<string, { tokens: number; last: number }> = new Map()
const MAX_TOKENS = 10
const REFILL_MS = 60 * 1000 // 10 tokens/min

export default function rateLimit(req: Request, res: Response, next: NextFunction) {
  const key = req.ip || (req.headers['x-forwarded-for'] as string) || 'unknown'
  const now = Date.now()
  const bucket = BUCKETS.get(key) || { tokens: MAX_TOKENS, last: now }
  const elapsed = now - bucket.last
  const refill = Math.floor(elapsed / REFILL_MS)
  if (refill > 0) {
    bucket.tokens = Math.min(MAX_TOKENS, bucket.tokens + refill)
    bucket.last = now
  }
  if (bucket.tokens <= 0) {
    res.status(429).json({ error: 'rate limit exceeded' })
    return
  }
  bucket.tokens -= 1
  BUCKETS.set(key, bucket)
  next()
}
