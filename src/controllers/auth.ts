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

import { Request, Response } from 'express'
import jwt from 'jsonwebtoken'
import { config } from '../config'
import { createUser, findUserByEmail, verifyUserPassword } from '../services/userService'
import { validateAPIKey } from '../services/apikeyService'
import { sendPasswordEmail, sendLoginNotificationEmail, sendPasswordResetEmail, addToResendAudience } from '../utils/mail'
import crypto from 'crypto'
import AppDataSource from '../data-source'
import { User } from '../entities/Entities'
import { createResetToken, getResetToken, deleteResetToken } from '../services/resetTokenService'

function generateResetToken() {
  return Math.random().toString(36).slice(2, 22)
}

function generateRandomPassword(length = 12) {
  return crypto.randomBytes(Math.ceil(length * 3 / 4)).toString('base64').replace(/\+/g, '0').replace(/\//g, '0').slice(0, length)
}

export class AuthController {
  async signup(req: Request, res: Response) {
    const { name, email } = req.body
    if (!email) return res.status(400).json({ error: 'email required' })
    const existing = await findUserByEmail(email)
    if (existing) return res.status(409).json({ error: 'user exists' })

    // generate random password and master password (to mirror Go behavior)
    const pw = generateRandomPassword(12)
    const masterPassword = generateRandomPassword(16)

    const u = await createUser(name || 'Unknown User', email, pw, masterPassword)
    const token = jwt.sign({ id: u.id, email: u.email }, config.JWT_SECRET, { expiresIn: '7d' })

    // send credentials email and report status
    let emailSent = false
    let emailError: any = null
    if (config.RESEND_API_KEY) {
      try {
        await sendPasswordEmail(email, u.name, pw, masterPassword)
        emailSent = true
      } catch (err) {
        emailError = String(err)
        console.error('welcome email failed:', err)
      }
    }

    // add to resend audience asynchronously (non-blocking)
    if (config.RESEND_API_KEY && config.RESEND_AUDIENCE_ID) {
      addToResendAudience(u.email, u.name).catch(err => console.error('addToResendAudience failed:', err))
    }

    const resp: any = { token, user: u, email_sent: emailSent }
    if (emailError) resp.email_error = emailError
    return res.status(201).json(resp)
  }

  async login(req: Request, res: Response) {
    // accept both camelCase and snake_case master password fields for compatibility
    const body: any = req.body || {}
    const email = body.email
    const password = body.password
    const masterPassword = body.masterPassword || body.master_password

    if (!email || !password || !masterPassword) return res.status(400).json({ error: 'email, password and masterPassword required' })

    const user = await findUserByEmail(email)
    if (!user) return res.status(401).json({ error: 'invalid credentials' })
    const ok = await verifyUserPassword(user, password)
    if (!ok) return res.status(401).json({ error: 'invalid credentials' })
    // verify master password
    const mpOk = user.masterPasswordHash ? await (await import('../utils/crypto')).verifyPassword(user.masterPasswordHash, masterPassword) : false
    if (!mpOk) return res.status(401).json({ error: 'invalid master password' })

    const token = jwt.sign({ id: user.id, email: user.email }, config.JWT_SECRET, { expiresIn: '7d' })

    // send login notification (non-blocking)
    try {
      const clientIP = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'Unknown'
      const userAgent = (req.headers['user-agent'] as string) || 'Unknown Browser/Device'
      sendLoginNotificationEmail(user.email, user.name, String(clientIP), String(userAgent)).catch(err => console.error('login email failed:', err))
    } catch (err) {
      console.error('login email trigger error:', err)
    }

    return res.json({ token, user })
  }

  async me(req: Request, res: Response) {
    const auth = (req.headers.authorization || '') as string
    if (!auth) return res.status(401).json({ error: 'unauthorized' })
    if (auth.startsWith('Bearer ')) {
      try {
        const p: any = jwt.verify(auth.slice(7), config.JWT_SECRET)
        return res.json({ id: p.id || null, email: p.email || p.sub || '' })
      } catch (err) {
        return res.status(401).json({ error: 'invalid token' })
      }
    }
    // try API key validation
    const user = await validateAPIKey(auth)
    if (user) return res.json({ id: user.id, email: user.email })
    return res.status(401).json({ error: 'invalid key' })
  }

  // POST /forgot-password
  async forgotPassword(req: Request, res: Response) {
    const { email } = req.body
    if (!email) return res.status(400).json({ error: 'email required' })
    const user = await findUserByEmail(email)
    if (!user) return res.status(404).json({ error: 'Email not registered' })

    // generate new credentials like the Go backend
    const password = generateRandomPassword(12)
    const masterPassword = generateRandomPassword(16)

    // update user password and master password hash
    const repo = AppDataSource.getRepository(User)
    user.password = await (await import('../utils/crypto')).hashPassword(password)
    user.masterPasswordHash = await (await import('../utils/crypto')).hashPassword(masterPassword)
    await repo.save(user)

    // create reset token record (for compatibility with reset flow) and send new credentials email
    try {
      const token = await createResetToken(user.id)
      await sendPasswordEmail(user.email, user.name, password, masterPassword)
      // also send a reset email with token for client compatibility
      await sendPasswordResetEmail(user.email, token).catch(() => {})
    } catch (err) {
      console.error('failed to send password email:', err)
      return res.status(500).json({ error: 'Failed to send password email' })
    }

    return res.json({ message: 'New password sent to your email' })
  }

  // POST /reset-password (keeps existing behavior)
  async resetPassword(req: Request, res: Response) {
    const { token, password } = req.body
    if (!token || !password) return res.status(400).json({ error: 'token and password required' })
    const rec = await getResetToken(token)
    if (!rec || rec.expiresAt < Date.now()) return res.status(400).json({ error: 'invalid or expired token' })
    // find user and update password
    const repo = AppDataSource.getRepository(User)
    const target = await repo.findOneBy({ id: rec.userId })
    if (!target) return res.status(404).json({ error: 'user not found' })
    target.password = await (await import('../utils/crypto')).hashPassword(password)
    await repo.save(target)
    await deleteResetToken(token)
    return res.json({ ok: true })
  }
}
