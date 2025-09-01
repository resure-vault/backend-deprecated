import express from 'express'
import { AuthController } from '../controllers/auth'
import { validateAPIKeyMiddleware } from '../middleware/auth'
import rateLimit from '../middleware/rateLimit'

const router = express.Router()
const ctl = new AuthController()

router.get('/health', (_req, res) => res.json({ ok: true }))
router.post('/signup', rateLimit, ctl.signup.bind(ctl))
router.post('/login', rateLimit, ctl.login.bind(ctl))
router.get('/me', validateAPIKeyMiddleware, ctl.me.bind(ctl))
router.post('/forgot-password', rateLimit, ctl.forgotPassword.bind(ctl))
router.post('/reset-password', rateLimit, ctl.resetPassword.bind(ctl))

export default router
