import { Request, Response } from 'express'

export class SecretsController {
  async list(req: Request, res: Response) {
    return res.json({ secrets: [] })
  }
  async create(req: Request, res: Response) {
    return res.status(201).json({ secret: null })
  }
  async get(req: Request, res: Response) {
    return res.json({ secret: null })
  }
  async update(req: Request, res: Response) {
    return res.json({ secret: null })
  }
  async delete(req: Request, res: Response) {
    return res.status(204).send()
  }
}
