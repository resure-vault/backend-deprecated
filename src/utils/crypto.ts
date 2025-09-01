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

// this file contains crypto helpers used across the server.
// all comments added by the assistant are lowercase as requested.
// responsibilities:
// - password hashing and verification
// - api key generation and hmac hashing
// - per-secret encryption and decryption using argon2id + xchacha20-poly1305
// notes:
// - ciphertext format is: v1$<salt_b64>$<nonce_b64>$<ct_b64>
// - argon2 parameters are chosen for moderate hardness; tune in production

import crypto from 'crypto'
import argon2 from 'argon2'
import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305'

const ARGON_TIME = 3
const ARGON_MEMORY = 65536
const ARGON_KEYLEN = 32
const SALT_LEN = 16
const NONCE_LEN = 24 // XChaCha20-Poly1305 nonce size

// hashPassword
// - wrapper around argon2.hash
// - returns a phc encoded argon2 string suitable for storage in users.password
// - keep this async so callers can await and surface errors cleanly
export async function hashPassword(password: string) {
  return await argon2.hash(password)
}

// verifyPassword
// - verify a plain password against a stored argon2 hash
// - returns true on match, false on any error or mismatch
export async function verifyPassword(hash: string, password: string) {
  try {
    return await argon2.verify(hash, password)
  } catch (err) {
    // verification failure or malformed hash -> treat as non-match
    return false
  }
}

// hashAPIKey
// - deterministic hmac-sha256 over a raw api key using a pepper value
// - the pepper must be secret and rotated carefully
// - stored value is hex digest
export function hashAPIKey(raw: string, pepper: string) {
  const hmac = crypto.createHmac('sha256', pepper)
  hmac.update(raw)
  return hmac.digest('hex')
}

// generateRawAPIKey
// - produce a human safe-ish prefix then 32 random bytes hex
// - callers should show the raw key once and persist only the hmac in db
export function generateRawAPIKey() {
  return 'svp_' + crypto.randomBytes(32).toString('hex')
}

// encrypt
// - produces ciphertext in versioned format the go backend expects: v1$salt$nonce$ciphertext
// - workflow:
//   1) generate random salt
//   2) derive a 32 byte key using argon2id with the salt
//   3) encrypt with xchacha20-poly1305 using a random 24 byte nonce
//   4) return base64 parts joined with dollar separators
// - note: callers must provide the password (master password) used to derive the key
export async function Encrypt(plaintext: string, password: string) {
  if (!password) throw new Error('password required')
  const salt = crypto.randomBytes(SALT_LEN)
  const threads = Math.max(1, require('os').cpus().length)

  // derive raw key via argon2id (returns Buffer when raw: true)
  const key = (await argon2.hash(password, {
    type: (argon2 as any).argon2id,
    salt,
    timeCost: ARGON_TIME,
    memoryCost: ARGON_MEMORY,
    parallelism: threads,
    hashLength: ARGON_KEYLEN,
    raw: true,
  } as any)) as Buffer

  const nonce = crypto.randomBytes(NONCE_LEN)
  const aead = new XChaCha20Poly1305(key)
  const ciphertext = aead.seal(nonce, Buffer.from(plaintext, 'utf8'))

  const bSalt = salt.toString('base64')
  const bNonce = nonce.toString('base64')
  const bCT = Buffer.from(ciphertext).toString('base64')

  return `v1$${bSalt}$${bNonce}$${bCT}`
}

// decrypt
// - accepts ciphertext in the v1 format and the password used to derive the key
// - derives key with the same argon2 parameters and attempts open()
// - throws on malformed input or failed authentication
export async function Decrypt(ciphertextStr: string, password: string) {
  if (!password || !ciphertextStr) throw new Error('password and ciphertext required')
  if (!ciphertextStr.startsWith('v1$')) {
    throw new Error('unsupported ciphertext format')
  }
  const parts = ciphertextStr.split('$')
  if (parts.length !== 4) throw new Error('malformed ciphertext')
  const salt = Buffer.from(parts[1], 'base64')
  const nonce = Buffer.from(parts[2], 'base64')
  const ct = Buffer.from(parts[3], 'base64')

  const threads = Math.max(1, require('os').cpus().length)
  const key = (await argon2.hash(password, {
    type: (argon2 as any).argon2id,
    salt,
    timeCost: ARGON_TIME,
    memoryCost: ARGON_MEMORY,
    parallelism: threads,
    hashLength: ARGON_KEYLEN,
    raw: true,
  } as any)) as Buffer // reminds me of my friend bufferwise :3

  const aead = new XChaCha20Poly1305(key)
  const plaintext = aead.open(nonce, ct)
  if (!plaintext) throw new Error('decryption failed')
  return Buffer.from(plaintext).toString('utf8')
}
