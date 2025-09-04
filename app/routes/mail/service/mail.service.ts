import { Resend } from 'resend';
import path from 'path';
import fs from 'fs/promises';
import mustache from 'mustache';
import { config } from '../../../config/config';
import type { WelcomeEmailData, LoginNotificationData, ResetPasswordData, MailResponse } from '../types/mail.types';

export class MailService {
  private static instance: MailService | null = null;
  private static configLogged: boolean = false;
  private resend: Resend;
  private audienceId: string;

  constructor() {
    const apiKey = config.resend.apiKey;
    if (!config.resend.audienceId) {
      throw new Error('RESEND_AUDIENCE_ID is not configured in config');
    }
    this.audienceId = config.resend.audienceId;
    
    if (!MailService.configLogged) {
      console.log('RESEND_API_KEY configured:', !!apiKey);
      console.log('RESEND_AUDIENCE_ID configured:', !!this.audienceId);
      MailService.configLogged = true;
    }
    
    if (!apiKey) {
      throw new Error('RESEND_API_KEY is not configured in config');
    }
    
    this.resend = new Resend(apiKey);
  }

  static getInstance(): MailService {
    if (!MailService.instance) {
      MailService.instance = new MailService();
    }
    return MailService.instance;
  }

  private async loadTemplate(templateName: string, data: Record<string, any>): Promise<string> {
    try {
      const templatePath = path.resolve(__dirname, '../html', `${templateName}.html`);
      console.log('Loading template from:', templatePath);
      
      const templateContent = await fs.readFile(templatePath, 'utf-8');
      return mustache.render(templateContent, data);
    } catch (error) {
      console.error('Template loading error:', error);
      const errorMessage = (error instanceof Error) ? error.message : String(error);
      throw new Error(`Failed to load template ${templateName}: ${errorMessage}`);
    }
  }

  async sendAccountCreationEmail(email: string, name: string, password: string, masterPassword: string): Promise<void> {
    try {
      console.log('Sending account creation email to:', email);
      console.log('Account creation email data:', { email, name, password: '***', masterPassword: '***' });

      const html = await this.loadTemplate('signup', {
        name: name,
        email: email,
        password: password,
        masterPassword: masterPassword
      });

      const result = await this.resend.emails.send({
        from: 'resure Support <support@yssh.dev>',
        to: [email],
        subject: 'Welcome to resure - Account Created Successfully',
        html
      });

      console.log('Resend API response:', JSON.stringify(result, null, 2));

      if (result.error) {
        console.error('Resend API error:', JSON.stringify(result.error, null, 2));
        throw new Error(`Resend API error: ${result.error.message}`);
      }

      console.log('Account creation email sent successfully:', result.data?.id);
    } catch (error) {
      console.error('Error sending account creation email:', error);
      throw error;
    }
  }

  async sendTestEmail(email: string): Promise<void> {
    try {
      console.log('Sending test email to:', email);

      const result = await this.resend.emails.send({
        from: 'resure Support <support@yssh.dev>',
        to: [email],
        subject: 'Test Email',
        html: '<div style="font-family: Arial, sans-serif; padding: 20px;"><h2>Test Email</h2><p>This is a test email to verify the mail service is working.</p></div>'
      });

      console.log('Test email Resend API response:', JSON.stringify(result, null, 2));

      if (result.error) {
        console.error('Test email Resend API error:', JSON.stringify(result.error, null, 2));
        throw new Error(`Resend API error: ${result.error.message}`);
      }

      console.log('Test email sent successfully:', result.data?.id);
    } catch (error) {
      console.error('Error sending test email:', error);
      throw error;
    }
  }

  async sendLoginNotification(email: string, data: LoginNotificationData): Promise<void> {
    try {
      console.log('Sending login notification to:', email);

      const html = await this.loadTemplate('login', {
        Name: data.name,
        LoginTime: data.loginTime,
        IP: data.ip,
        Browser: data.browser
      });

      const result = await this.resend.emails.send({
        from: 'resure Support <support@yssh.dev>',
        to: [email],
        subject: 'New Login Detected',
        html
      });

      console.log('Login notification Resend API response:', JSON.stringify(result, null, 2));

      if (result.error) {
        console.error('Login notification Resend API error:', JSON.stringify(result.error, null, 2));
        throw new Error(`Resend API error: ${result.error.message}`);
      }

      console.log('Login notification sent successfully:', result.data?.id);
    } catch (error) {
      console.error('Error sending login notification:', error);
    }
  }

  async sendResetPassword(email: string, data: ResetPasswordData): Promise<void> {
    try {
      console.log('Sending password reset email to:', email);

      const html = await this.loadTemplate('reset', {
        reset_url: data.reset_url
      });

      const result = await this.resend.emails.send({
        from: 'resure Support <support@yssh.dev>',
        to: [email],
        subject: 'Password Reset Instructions',
        html
      });

      console.log('Password reset Resend API response:', JSON.stringify(result, null, 2));

      if (result.error) {
        console.error('Password reset Resend API error:', JSON.stringify(result.error, null, 2));
        throw new Error(`Resend API error: ${result.error.message}`);
      }

      console.log('Password reset email sent successfully:', result.data?.id);
    } catch (error) {
      console.error('Error sending password reset email:', error);
      throw error;
    }
  }

  async sendCustomEmail(email: string, subject: string, content: string): Promise<MailResponse> {
    try {
      console.log('Sending custom email to:', email);

      const result = await this.resend.emails.send({
        from: 'resure Support <support@yssh.dev>',
        to: [email],
        subject,
        html: content
      });

      console.log('Custom email Resend API response:', JSON.stringify(result, null, 2));

      if (result.error) {
        console.error('Custom email Resend API error:', JSON.stringify(result.error, null, 2));
        return {
          success: false,
          message: 'Failed to send email',
          error: result.error.message
        };
      }

      console.log('Custom email sent successfully:', result.data?.id);
      return {
        success: true,
        messageId: result.data?.id,
        message: 'Email sent successfully'
      };
    } catch (error: any) {
      console.error('Error sending custom email:', error);
      return {
        success: false,
        message: 'Failed to send email',
        error: error.message
      };
    }
  }

  async verifyConnection(): Promise<boolean> {
    try {
      console.log('Verifying Resend connection...');
      const result = await this.resend.domains.list();
      console.log('Resend connection verification result:', JSON.stringify(result, null, 2));
      return !result.error;
    } catch (error) {
      console.error('Error verifying Resend connection:', error);
      return false;
    }
  }

  async addEmailToAudience(email: string, firstName?: string, lastName?: string): Promise<any> {
    try {
      console.log('Adding email to audience:', email);
      const result = await this.resend.contacts.create({
        audienceId: this.audienceId,
        email,
        firstName: firstName || '',
        lastName: lastName || ''
      });
      console.log('Add to audience result:', JSON.stringify(result, null, 2));
      return result;
    } catch (error) {
      console.error('Error adding email to audience:', error);
      throw error;
    }
  }

  async getAudienceContacts(): Promise<any> {
    try {
      const result = await this.resend.contacts.list({
        audienceId: this.audienceId
      });
      console.log('Get audience contacts result:', JSON.stringify(result, null, 2));
      return result;
    } catch (error) {
      console.error('Error getting audience contacts:', error);
      throw error;
    }
  }

  async removeEmailFromAudience(email: string): Promise<any> {
    try {
      const contactsResult = await this.getAudienceContacts();
      const contact = contactsResult.data?.data?.find((c: any) => c.email === email);
      
      if (!contact) {
        throw new Error('Email not found in audience');
      }

      const result = await this.resend.contacts.remove({
        audienceId: this.audienceId,
        id: contact.id
      });
      console.log('Remove from audience result:', JSON.stringify(result, null, 2));
      return result;
    } catch (error) {
      console.error('Error removing email from audience:', error);
      throw error;
    }
  }

  async sendBroadcastEmail(subject: string, htmlContent: string, textContent?: string): Promise<any> {
    try {
      const contactsResult = await this.getAudienceContacts();
      const contacts = contactsResult.data?.data || [];
      
      if (contacts.length === 0) {
        throw new Error('No contacts found in audience');
      }

      const emails = contacts.map((contact: any) => contact.email);

      const result = await this.resend.emails.send({
        from: 'resure Team <support@yssh.dev>',
        to: emails,
        subject,
        html: htmlContent,
        text: textContent
      });

      console.log('Broadcast email result:', JSON.stringify(result, null, 2));
      return result;
    } catch (error) {
      console.error('Error sending broadcast email:', error);
      throw error;
    }
  }
}
