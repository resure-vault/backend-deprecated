import crypto from 'crypto'
import argon2 from 'argon2'
import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305'

// Argon2id params to match Go defaults (but keep reasonable performance)
const ARGON_TIME = 3
const ARGON_MEMORY = 65536
const ARGON_KEYLEN = 32
const SALT_LEN = 16
const NONCE_LEN = 24 // XChaCha20-Poly1305 nonce size

export async function hashPassword(password: string) {
  return await argon2.hash(password)
}

export async function verifyPassword(hash: string, password: string) {
  try {
    return await argon2.verify(hash, password)
  } catch (err) {
    return false
  }
}

export function hashAPIKey(raw: string, pepper: string) {
  const hmac = crypto.createHmac('sha256', pepper)
  hmac.update(raw)
  return hmac.digest('hex')
}

export function generateRawAPIKey() {
  return 'svp_' + crypto.randomBytes(32).toString('hex')
}

// Encrypt produces Go-compatible format: v1$<salt_b64>$<nonce_b64>$<ct_b64>
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
  } as any)) as Buffer // reminds me of my friend bufferwise :P

  const aead = new XChaCha20Poly1305(key)
  const plaintext = aead.open(nonce, ct)
  if (!plaintext) throw new Error('decryption failed')
  return Buffer.from(plaintext).toString('utf8')
}
