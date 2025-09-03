import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { logger } from '../../../common/logger';
import { MailService } from '../../mail/service/mail.service';
import * as authSchema from '../../../microservices/schema/schema';
import type { 
  CreateUserRequest, 
  LoginRequest, 
  UserResponse, 
  AuthResponse,
  UpdateProfileRequest,
  ChangePasswordRequest,
  SessionData,
  GeneratedPasswords
} from '../types/user.types';

interface BetterAuthContext {
  path: string;
  method: string;
  body: any;
  headers: Record<string, string>;
  user?: any;
  session?: any;
  request: any;
}

interface BetterAuthCallbackContext {
  context: BetterAuthContext;
  request: any;
}

export class UserService {
  private readonly mailService: MailService;
  private readonly auth: any;
  private readonly db: any;

  constructor(db: any) {
    this.db = db;
    this.mailService = new MailService();
    
    this.auth = betterAuth({
      database: drizzleAdapter(db, {
        provider: "pg",
        schema: {
          user: authSchema.users,
          session: authSchema.sessions,
          account: authSchema.accounts,
          verificationToken: authSchema.verificationTokens,
        },
      }),
      emailAndPassword: {
        enabled: true,
        requireEmailVerification: true,
        sendResetPassword: async ({ user, url }: { user: any; url: string }): Promise<void> => {
          await this.sendPasswordResetEmail(user.email, url);
        },
      },
      user: {
        additionalFields: {
          name: {
            type: "string",
            required: false,
          },
          masterPassword: {
            type: "string",
            required: true,
          },
        },
      },
      session: {
        cookieCache: {
          enabled: true,
          maxAge: 60 * 60 * 24 * 7,
        },
      },
      callbacks: {
        after: [
          {
            matcher: (context: BetterAuthContext): boolean => context.path === "/sign-up",
            handler: async (ctx: BetterAuthCallbackContext): Promise<void> => {
              if (ctx.context.user) {
                logger.info('User registration completed', { userId: ctx.context.user.id });
              }
            },
          },
          {
            matcher: (context: BetterAuthContext): boolean => context.path === "/sign-in",
            handler: async (ctx: BetterAuthCallbackContext): Promise<void> => {
              if (ctx.context.user) {
                await this.handleUserLogin(ctx.context.user, ctx.request);
              }
            },
          },
        ],
      },
    });
  }

  async signup(data: CreateUserRequest): Promise<AuthResponse> {
    try {
      logger.info('User signup attempt initiated', { email: data.email });

      const passwords = this.generatePasswords();
      const name = this.extractNameFromEmail(data.email);

      const result = await this.auth.api.signUpEmail({
        body: {
          email: data.email,
          password: passwords.loginPassword,
          name: name,
          masterPassword: await this.hashPassword(passwords.masterPassword),
        },
      });

      if (result.error) {
        logger.error('User signup failed', new Error(result.error.message), { email: data.email });
        return {
          success: false,
          message: result.error.message,
          error: result.error.message,
        };
      }

      await this.handleUserRegistration(result.data.user, passwords);

      logger.info('User signup completed successfully', { 
        email: data.email,
        userId: result.data.user.id 
      });

      return {
        success: true,
        message: 'Account created successfully. Please verify your email to continue.',
        user: this.transformUserData(result.data.user),
        loginPassword: passwords.loginPassword,
        masterPassword: passwords.masterPassword,
      };
    } catch (error: any) {
      logger.error('User signup error', error, { email: data.email });
      return {
        success: false,
        message: 'Account creation failed',
        error: error.message,
      };
    }
  }

  async login(data: LoginRequest): Promise<AuthResponse> {
    try {
      logger.info('User login attempt initiated', { email: data.email });

      const result = await this.auth.api.signInEmail({
        body: {
          email: data.email,
          password: data.password,
        },
      });

      if (result.error) {
        logger.error('User login failed', new Error(result.error.message), { email: data.email });
        return {
          success: false,
          message: result.error.message,
          error: result.error.message,
        };
      }

      logger.info('User login completed successfully', { 
        email: data.email,
        userId: result.data.user.id 
      });

      return {
        success: true,
        message: 'Authentication successful',
        user: this.transformUserData(result.data.user),
        token: result.data.session.token,
      };
    } catch (error: any) {
      logger.error('User login error', error, { email: data.email });
      return {
        success: false,
        message: 'Authentication failed',
        error: error.message,
      };
    }
  }

  async logout(sessionToken: string): Promise<{ success: boolean; message: string }> {
    try {
      await this.auth.api.signOut({
        headers: {
          authorization: `Bearer ${sessionToken}`,
        },
      });

      logger.info('User logout completed', { sessionToken });

      return {
        success: true,
        message: 'Session terminated successfully',
      };
    } catch (error: any) {
      logger.error('User logout error', error, { sessionToken });
      return {
        success: false,
        message: 'Session termination failed',
      };
    }
  }

  async verifyEmail(token: string): Promise<AuthResponse> {
    try {
      const result = await this.auth.api.verifyEmail({
        body: { token },
      });

      if (result.error) {
        logger.error('Email verification failed', new Error(result.error.message), { token });
        return {
          success: false,
          message: result.error.message,
          error: result.error.message,
        };
      }

      logger.info('Email verification completed', { userId: result.data.user.id });

      return {
        success: true,
        message: 'Email verification successful',
        user: this.transformUserData(result.data.user),
      };
    } catch (error: any) {
      logger.error('Email verification error', error, { token });
      return {
        success: false,
        message: 'Email verification failed',
        error: error.message,
      };
    }
  }

  async requestPasswordReset(email: string): Promise<{ success: boolean; message: string }> {
    try {
      logger.info('Password reset requested', { email });

      const result = await this.auth.api.forgetPassword({
        body: { email },
      });

      if (result.error) {
        logger.error('Password reset request failed', new Error(result.error.message), { email });
        return {
          success: false,
          message: result.error.message,
        };
      }

      logger.info('Password reset email dispatched', { email });

      return {
        success: true,
        message: 'Password reset instructions sent',
      };
    } catch (error: any) {
      logger.error('Password reset request error', error, { email });
      return {
        success: false,
        message: 'Password reset request failed',
      };
    }
  }

  async resetPassword(token: string, password: string): Promise<AuthResponse> {
    try {
      const result = await this.auth.api.resetPassword({
        body: { token, password },
      });

      if (result.error) {
        logger.error('Password reset failed', new Error(result.error.message), { token });
        return {
          success: false,
          message: result.error.message,
          error: result.error.message,
        };
      }

      logger.info('Password reset completed', { userId: result.data.user.id });

      return {
        success: true,
        message: 'Password updated successfully',
        user: this.transformUserData(result.data.user),
      };
    } catch (error: any) {
      logger.error('Password reset error', error, { token });
      return {
        success: false,
        message: 'Password reset failed',
        error: error.message,
      };
    }
  }

  async updateProfile(userId: string, data: UpdateProfileRequest): Promise<AuthResponse> {
    try {
      logger.info('Profile update initiated', { userId });

      const result = await this.auth.api.updateUser({
        body: {
          id: userId,
          ...data,
        },
      });

      if (result.error) {
        logger.error('Profile update failed', new Error(result.error.message), { userId });
        return {
          success: false,
          message: result.error.message,
          error: result.error.message,
        };
      }

      logger.info('Profile updated successfully', { userId });

      return {
        success: true,
        message: 'Profile updated successfully',
        user: this.transformUserData(result.data),
      };
    } catch (error: any) {
      logger.error('Profile update error', error, { userId });
      return {
        success: false,
        message: 'Profile update failed',
        error: error.message,
      };
    }
  }

  async changePassword(userId: string, data: ChangePasswordRequest): Promise<{ success: boolean; message: string }> {
    try {
      logger.info('Password change initiated', { userId });

      const user = await this.auth.api.getUser({ userId });
      if (!user || !await this.verifyPassword(data.currentPassword, user.password)) {
        return {
          success: false,
          message: 'Current password verification failed',
        };
      }

      const hashedPassword = await this.hashPassword(data.newPassword);
      await this.auth.api.updateUser({
        body: {
          id: userId,
          password: hashedPassword,
        },
      });

      logger.info('Password change completed', { userId });

      return {
        success: true,
        message: 'Password updated successfully',
      };
    } catch (error: any) {
      logger.error('Password change error', error, { userId });
      return {
        success: false,
        message: 'Password change failed',
      };
    }
  }

  async validateSession(token: string): Promise<SessionData | null> {
    try {
      const result = await this.auth.api.getSession({
        headers: {
          authorization: `Bearer ${token}`,
        },
      });

      if (result.error || !result.data) {
        return null;
      }

      return {
        userId: result.data.user.id,
        email: result.data.user.email,
        name: result.data.user.name,
        sessionId: result.data.session.id,
      };
    } catch (error: any) {
      logger.error('Session validation error', error, { token });
      return null;
    }
  }

  async verifyMasterPassword(userId: string, masterPassword: string): Promise<boolean> {
    try {
      const user = await this.auth.api.getUser({ userId });
      if (!user || !user.masterPassword) {
        return false;
      }

      return await this.verifyPassword(masterPassword, user.masterPassword);
    } catch (error: any) {
      logger.error('Master password verification error', error, { userId });
      return false;
    }
  }

  private generatePasswords(): GeneratedPasswords {
    return {
      loginPassword: this.generateSecurePassword(12),
      masterPassword: this.generateSecurePassword(16),
    };
  }

  private generateSecurePassword(length: number): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = crypto.randomInt(0, charset.length);
      password += charset[randomIndex];
    }
    
    return password;
  }

  private extractNameFromEmail(email: string): string {
    if (!email || !email.includes('@')) {
      return 'user';
    }
    
    const parts = email.split('@');
    return parts[0] || 'user';
  }  

  private async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 12);
  }

  private async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  private async handleUserRegistration(user: any, passwords: GeneratedPasswords): Promise<void> {
    try {
      await this.mailService.sendWelcomeEmail(user.email, {
        name: user.name,
        email: user.email,
        password: passwords.loginPassword,
        masterPassword: passwords.masterPassword,
      });

      logger.info('Welcome email dispatched', { userId: user.id, email: user.email });
    } catch (error: any) {
      logger.error('Welcome email dispatch failed', error, { 
        userId: user.id, 
        email: user.email 
      });
    }
  }

  private async handleUserLogin(user: any, request: any): Promise<void> {
    try {
      const clientInfo = this.extractClientInfo(request);

      await this.mailService.sendLoginNotification(user.email, {
        name: user.name,
        loginTime: new Date().toLocaleString(),
        ip: clientInfo.ip,
        browser: clientInfo.userAgent,
      });

      logger.info('Login notification dispatched', { 
        userId: user.id, 
        email: user.email, 
        ip: clientInfo.ip 
      });
    } catch (error: any) {
      logger.error('Login notification dispatch failed', error, { 
        userId: user.id, 
        email: user.email 
      });
    }
  }

  private extractClientInfo(request: any): { ip: string; userAgent: string } {
    return {
      ip: request.headers?.['x-forwarded-for'] || request.connection?.remoteAddress || 'Unknown',
      userAgent: request.headers?.['user-agent'] || 'Unknown',
    };
  }

  private async sendPasswordResetEmail(email: string, resetUrl: string): Promise<void> {
    try {
      await this.mailService.sendResetPassword(email, { reset_url: resetUrl });
      logger.info('Password reset email dispatched', { email });
    } catch (error: any) {
      logger.error('Password reset email dispatch failed', error, { email });
    }
  }

  private transformUserData(user: any): UserResponse {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      emailVerified: user.emailVerified || false,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }
}
