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

// secret service
// helper functions to list, create and retrieve secrets from the database
// responsibilities:
// - store encrypted secret blobs using src/utils/crypto.Encrypt
// - decrypt secrets for authorized callers using Decrypt
// - note: errors from Decrypt bubble up so caller can decide how to handle them

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
