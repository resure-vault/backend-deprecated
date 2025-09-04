import express from 'express';
import type { Request, Response } from 'express';
import { MailService } from '../service/mail.service';

const router = express.Router();
const mailService = MailService.getInstance();

router.post('/send', async (req, res) => {
  try {
    const { email, subject, content } = req.body;
    if (!email || !subject || !content) {
      return res.status(400).json({ error: 'Email, subject and content are required' });
    }
    const result = await mailService.sendCustomEmail(email, subject, content);
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/test-connection', async (req, res) => {
  try {
    const success = await mailService.verifyConnection();
    res.json({ 
      success, 
      message: success ? 'Connection successful' : 'Connection failed' 
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/test-send', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    await mailService.sendTestEmail(email);
    res.json({ success: true, message: 'Test email sent' });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/send/login-notification', async (req, res) => {
  try {
    const { email, name, loginTime, ip, browser } = req.body;
    if (!email || !name || !loginTime || !ip || !browser) {
      return res.status(400).json({ error: 'All fields required' });
    }
    await mailService.sendLoginNotification(email, { name, loginTime, ip, browser });
    res.json({ success: true, message: 'Login notification sent' });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/send/reset-password', async (req, res) => {
  try {
    const { email, reset_url } = req.body;
    if (!email || !reset_url) {
      return res.status(400).json({ error: 'Email and reset URL required' });
    }
    await mailService.sendResetPassword(email, { reset_url });
    res.json({ success: true, message: 'Reset email sent' });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/audience/add', async (req, res) => {
  try {
    const { email, firstName, lastName } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    const result = await mailService.addEmailToAudience(email, firstName, lastName);
    res.json({ success: true, data: result });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/audience/remove', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    const result = await mailService.removeEmailFromAudience(email);
    res.json({ success: true, data: result });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/audience/broadcast', async (req, res) => {
  try {
    const { subject, html, text } = req.body;
    if (!subject || !html) {
      return res.status(400).json({ error: 'Subject and HTML content required' });
    }
    const result = await mailService.sendBroadcastEmail(subject, html, text);
    res.json({ success: true, data: result });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/audience/contacts', async (req, res) => {
  try {
    const contacts = await mailService.getAudienceContacts();
    res.json({ success: true, data: contacts });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
