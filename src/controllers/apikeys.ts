import { Request, Response } from 'express'
import AppDataSource from '../data-source'
import { APIKey, User } from '../entities/Entities'
import { createAPIKeyForUser } from '../services/apikeyService'

export class APIKeysController {
  async list(req: Request, res: Response) {
    const user: User = (req as any).user
    const page = parseInt(String(req.query.page || '1'), 10)
    const limit = parseInt(String(req.query.limit || '20'), 10)
    const repo = AppDataSource.getRepository(APIKey)
    const [items, total] = await repo.findAndCount({ where: { userId: user.id }, order: { createdAt: 'DESC' }, take: limit, skip: (page - 1) * limit })
    // hide key material
    items.forEach(i => (i.key = 'Hidden'))
    res.json({ api_keys: items, pagination: { page, limit, total } })
  }

  async create(req: Request, res: Response) {
    const user: User = (req as any).user
    const { name } = req.body
    if (!name || String(name).trim() === '') return res.status(400).json({ error: 'Name required' })
    const repo = AppDataSource.getRepository(APIKey)
    const exists = await repo.findOneBy({ userId: user.id, name })
    if (exists) return res.status(409).json({ error: 'Name exists' })
    const result = await createAPIKeyForUser(user, name)
    res.status(201).json({ api_key: result, warning: 'Store securely - shown only once' })
  }

  async revoke(req: Request, res: Response) {
    const user: User = (req as any).user
    const id = parseInt(req.params.id, 10)
    const repo = AppDataSource.getRepository(APIKey)
    const key = await repo.findOneBy({ id, userId: user.id })
    if (!key) return res.status(404).json({ error: 'Not found' })
    key.isActive = false
    await repo.save(key)
    res.json({ id: key.id, name: key.name })
  }
}
