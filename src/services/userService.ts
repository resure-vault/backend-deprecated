import AppDataSource from '../data-source'
import { User } from '../entities/Entities'
import { hashPassword, verifyPassword } from '../utils/crypto'

export async function createUser(name: string, email: string, password: string, masterPassword?: string): Promise<User> {
  const userRepo = AppDataSource.getRepository(User)
  const hashed = await hashPassword(password)
  const u: Partial<User> = { name, email, password: hashed }
  if (masterPassword) {
    u.masterPasswordHash = await hashPassword(masterPassword)
  }
  // ensure timestamps are present so inserts do not write NULL
  const now = new Date()
  ;(u as any).createdAt = now
  ;(u as any).updatedAt = now
  const created = userRepo.create(u as User)
  const saved = await userRepo.save(created as User)
  return saved as User
}

export async function findUserByEmail(email: string): Promise<User | null> {
  const userRepo = AppDataSource.getRepository(User)
  return await userRepo.findOneBy({ email })
}

export async function verifyUserPassword(user: User, password: string) {
  return await verifyPassword(user.password, password)
}
