import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import { config } from '../config'
import { validateAPIKey } from '../services/apikeyService'

export async function validateAPIKeyMiddleware(req: Request, res: Response, next: NextFunction) {
  const auth = (req.headers.authorization || '') as string
  if (!auth) return res.status(401).json({ error: 'unauthorized' })
  if (auth.startsWith('Bearer ')) {
    try {
      const p: any = jwt.verify(auth.slice(7), config.JWT_SECRET)
      // attach user minimal info
      ;(req as any).user = { id: p.id, email: p.email }
      return next()
    } catch (err) {
      return res.status(401).json({ error: 'invalid token' })
    }
  }
  const user = await validateAPIKey(auth)
  if (!user) return res.status(401).json({ error: 'invalid key' })
  ;(req as any).user = user
  return next()
}
