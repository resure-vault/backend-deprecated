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

// user service
// helper functions to create and query users
// handles hashing passwords and master passwords via src/utils/crypto.ts
// ensure timestamps are set when creating records to avoid nulls in the db

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
