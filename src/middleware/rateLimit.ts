import { Request, Response, NextFunction } from 'express'

const BUCKETS: Map<string, { tokens: number; last: number }> = new Map()
const MAX_TOKENS = 10
const REFILL_MS = 60 * 1000 // 10 tokens per minute

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
