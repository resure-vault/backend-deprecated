import { Resend } from 'resend';
import path from 'path';
import fs from 'fs/promises';
import mustache from 'mustache';
import type { WelcomeEmailData, LoginNotificationData, ResetPasswordData, MailResponse } from '../types/mail.types';

export class MailService {
  private resend: Resend;
  private audienceId: string;

  constructor() {
    const apiKey = process.env.RESEND_API_KEY;
    this.audienceId = process.env.RESEND_AUDIENCE_ID || '';
    
    if (!apiKey) {
      throw new Error('RESEND_API_KEY is not configured');
    }
    
    this.resend = new Resend(apiKey);
  }

  private async loadTemplate(templateName: string, data: Record<string, any>): Promise<string> {
    const templatePath = path.resolve(__dirname, '../html', `${templateName}.html`);
    const templateContent = await fs.readFile(templatePath, 'utf-8');
    return mustache.render(templateContent, data);
  }

  async sendWelcomeEmail(email: string, data: WelcomeEmailData): Promise<void> {
    const html = await this.loadTemplate('welcome', {
      Name: data.name,
      Email: data.email,
      Password: data.password,
      MasterPassword: data.masterPassword
    });

    await this.resend.emails.send({
      from: 'resure Support <support@resure.tech>',
      to: [email],
      subject: 'Welcome to resure',
      html
    });
  }

  async sendLoginNotification(email: string, data: LoginNotificationData): Promise<void> {
    const html = await this.loadTemplate('login', {
      Name: data.name,
      LoginTime: data.loginTime,
      IP: data.ip,
      Browser: data.browser
    });

    await this.resend.emails.send({
      from: 'resure Support <support@resure.tech>',
      to: [email],
      subject: 'New Login Detected',
      html
    });
  }

  async sendResetPassword(email: string, data: ResetPasswordData): Promise<void> {
    const html = await this.loadTemplate('reset', {
      reset_url: data.reset_url
    });

    await this.resend.emails.send({
      from: 'resure Support <support@resure.tech>',
      to: [email],
      subject: 'Password Reset Instructions',
      html
    });
  }

  async sendCustomEmail(email: string, subject: string, content: string): Promise<MailResponse> {
    try {
      const result = await this.resend.emails.send({
        from: 'resure Support <support@resure.tech>',
        to: [email],
        subject,
        html: content
      });

      if (result.error) {
        return {
          success: false,
          message: 'Failed to send email',
          error: result.error.message
        };
      }

      return {
        success: true,
        messageId: result.data?.id,
        message: 'Email sent successfully'
      };
    } catch (error: any) {
      return {
        success: false,
        message: 'Failed to send email',
        error: error.message
      };
    }
  }

  async verifyConnection(): Promise<boolean> {
    try {
      const result = await this.resend.domains.list();
      return !result.error;
    } catch {
      return false;
    }
  }

  async sendTestEmail(email: string): Promise<void> {
    await this.resend.emails.send({
      from: 'resure Support <support@resure.tech>',
      to: [email],
      subject: 'Test Email',
      html: '<div style="font-family: Arial, sans-serif; padding: 20px;"><h2>Test Email</h2><p>This is a test email.</p></div>'
    });
  }

  async addEmailToAudience(email: string, firstName?: string, lastName?: string): Promise<any> {
    return await this.resend.contacts.create({
      audienceId: this.audienceId,
      email,
      firstName: firstName || '',
      lastName: lastName || ''
    });
  }

  async getAudienceContacts(): Promise<any> {
    return await this.resend.contacts.list({
      audienceId: this.audienceId
    });
  }

  async removeEmailFromAudience(email: string): Promise<any> {
    const contactsResult = await this.getAudienceContacts();
    const contact = contactsResult.data?.data?.find((c: any) => c.email === email);
    
    if (!contact) {
      throw new Error('Email not found in audience');
    }

    return await this.resend.contacts.remove({
      audienceId: this.audienceId,
      id: contact.id
    });
  }

  async sendBroadcastEmail(subject: string, htmlContent: string, textContent?: string): Promise<any> {
    const contactsResult = await this.getAudienceContacts();
    const contacts = contactsResult.data?.data || [];
    
    if (contacts.length === 0) {
      throw new Error('No contacts found in audience');
    }

    const emails = contacts.map((contact: any) => contact.email);

    return await this.resend.emails.send({
      from: 'resure Team <support@resure.tech>',
      to: emails,
      subject,
      html: htmlContent,
      text: textContent
    });
  }
}
