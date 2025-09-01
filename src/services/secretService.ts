import AppDataSource from '../data-source'
import { Secret } from '../entities/Entities'
import { Encrypt, Decrypt } from '../utils/crypto'

export async function listSecretsForUser(userId: number, page: number, limit: number) {
  const repo = AppDataSource.getRepository(Secret)
  const [items, total] = await repo.findAndCount({ where: { userId }, take: limit, skip: (page - 1) * limit })
  return { items, total }
}

export async function createSecret(userId: number, name: string, value: string, masterPassword: string) {
  const repo = AppDataSource.getRepository(Secret)
  const enc = await Encrypt(value, masterPassword)
  const s = repo.create({ userId, name, value: enc })
  await repo.save(s)
  return s
}

export async function getSecret(id: number, masterPassword: string) {
  const repo = AppDataSource.getRepository(Secret)
  const s = await repo.findOneBy({ id })
  if (!s) return null
  try {
    const dec = await Decrypt(s.value, masterPassword)
    return { ...s, value: dec }
  } catch (err) {
    throw new Error('decryption failed')
  }
}
