import { Resend } from 'resend'
import { config } from '../config'
import fs from 'fs'
import path from 'path'

const resend = new Resend(config.RESEND_API_KEY)
const FROM = 'Secured <noreply@yssh.dev>'

async function sendWithRetry(payload: any, attempts = 3) {
  let lastErr: any
  for (let i = 0; i < attempts; i++) {
    try {
      console.log(`resend: attempt ${i + 1} to ${payload.to}`)
      const resp = await resend.emails.send(payload)
      console.log('resend: sent response', resp)
      return resp
    } catch (err) {
      lastErr = err
      console.error(`resend: attempt ${i + 1} failed:`, err)
      // exponential backoff
      await new Promise(r => setTimeout(r, 500 * Math.pow(2, i)))
    }
  }
  console.error('resend: all attempts failed', lastErr)
  throw lastErr
}

function loadTemplate(name: string) {
  const tplPath = path.resolve(process.cwd(), 'templates', name)
  if (fs.existsSync(tplPath)) {
    return fs.readFileSync(tplPath, 'utf8')
  }
  return null
}

function escapeHtml(str: string) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;')
}

function renderTemplate(tpl: string, vars: Record<string, string>) {
  let out = tpl
  for (const k of Object.keys(vars)) {
    const v = vars[k] || ''
    const safe = escapeHtml(v)
    // replace {{.Key}} and {{Key}} with optional whitespace
    const re1 = new RegExp(`{{\\s*\\.?${k}\\s*}}`, 'g')
    out = out.replace(re1, safe)
  }
  return out
}

function formatLoginTime(d = new Date()) {
  // produce format similar to: "January 2, 2006 at 3:04 PM MST"
  const parts = d.toLocaleString('en-US', {
    month: 'long',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    hour12: true,
    timeZoneName: 'short',
  })
  // parts example: "August 31, 2025 at 3:04 PM GMT+0" or "August 31, 2025, 3:04 PM GMT"
  // normalize to use " at " between date and time
  return parts.replace(/,\s*/, ' at ')
}

export async function sendPasswordEmail(to: string, name: string, password: string, masterPassword: string) {
  const tpl = loadTemplate('welcome.html') || `<p>Your account has been created. Email: {{.Email}} Password: {{.Password}} Master: {{.MasterPassword}}</p>`
  const html = renderTemplate(tpl, {
    Name: name,
    Email: to,
    Password: password,
    MasterPassword: masterPassword,
  })

  const payload = {
    from: FROM,
    to,
    subject: 'Welcome to Secured - Your Account Credentials',
    html,
  }
  return await sendWithRetry(payload)
}

export async function sendLoginNotificationEmail(to: string, name: string, ipAddress: string, userAgent: string) {
  const tpl = loadTemplate('login.html') || `<p>New login for {{.Name}} from {{.IP}} at {{.LoginTime}} using {{.Browser}}</p>`
  const loginTime = formatLoginTime(new Date())
  const html = renderTemplate(tpl, {
    Name: name,
    LoginTime: loginTime,
    IP: ipAddress,
    Browser: userAgent,
  })

  const payload = {
    from: FROM,
    to,
    subject: 'New Login to Your Secured Account',
    html,
  }
  return await sendWithRetry(payload)
}

export async function sendWelcomeEmail(to: string, token: string) {
  // keep a simple token welcome fallback but prefer welcome.html if present
  const tpl = loadTemplate('welcome.html') || `<p>Welcome to Secrets Vault!</p><p>Your token: {{token}}</p>`
  const html = renderTemplate(tpl, { token })
  const payload = { from: FROM, to, subject: 'Welcome to Secrets Vault', html }
  return await sendWithRetry(payload)
}

export async function sendPasswordResetEmail(to: string, token: string) {
  const resetURL = `${process.env.FRONTEND_URL || 'https://example.com'}/reset-password?token=${encodeURIComponent(token)}`
  const tpl = loadTemplate('reset.html') || `<p>Reset your password by visiting <a href="${resetURL}">this link</a></p><p>If you didn't request this, ignore.</p>`
  const html = renderTemplate(tpl, { reset_url: resetURL, token })
  const payload = {
    from: FROM,
    to,
    subject: 'Reset your Secrets Vault password',
    html,
  }
  return await sendWithRetry(payload)
}

export async function addToResendAudience(email: string, name: string) {
  if (!config.RESEND_AUDIENCE_ID) {
    console.warn('RESEND_AUDIENCE_ID not configured, skipping addToResendAudience')
    return
  }
  try {
    if ((resend as any).contacts && typeof (resend as any).contacts.create === 'function') {
      await (resend as any).contacts.create({ email, first_name: name, audience_id: config.RESEND_AUDIENCE_ID })
      return
    }
    // fallback: attempt create via .contacts.create with different casing
    if ((resend as any).contacts && typeof (resend as any).contacts.create === 'function') {
      await (resend as any).contacts.create({ email, firstName: name, audienceId: config.RESEND_AUDIENCE_ID })
      return
    }
    console.warn('resend SDK does not expose contacts.create; cannot add to audience')
  } catch (err) {
    console.error('addToResendAudience failed:', err)
  }
}
