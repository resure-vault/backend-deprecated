import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { logger } from '../../../common/logger';
import { MailService } from '../../mail/service/mail.service';
import * as authSchema from '../../../microservices/schema/schema';
import { eq } from 'drizzle-orm';
import { getErrorMessage } from '../../../utils/error';
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
    this.mailService = MailService.getInstance();
    
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
        requireEmailVerification: false,
      },
      session: {
        cookieCache: {
          enabled: true,
          maxAge: 604800,
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
      logger.info('User signup attempt', { email: data.email });
      
      // Generate secure passwords
      const passwords = this.generatePasswords();
      const name = this.extractNameFromEmail(data.email);
      
      // Hash passwords
      const hashedLoginPassword = await this.hashPassword(passwords.loginPassword);
      const hashedMasterPassword = await this.hashPassword(passwords.masterPassword);
      
      // Direct database insertion
      const [user] = await this.db.insert(authSchema.users).values({
        email: data.email,
        name: name,
        password: hashedLoginPassword,
        masterPassword: hashedMasterPassword,
        emailVerified: false,
        emailVerificationToken: null,
        resetPasswordToken: null,
        resetPasswordExpires: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      }).returning();

      // Send welcome email with resure branding
      await this.mailService.sendAccountCreationEmail(
        user.email, 
        user.name, 
        passwords.loginPassword,
        passwords.masterPassword
      );

      logger.info('User signup completed', { email: data.email, userId: user.id });

      return {
        success: true,
        message: 'Account created successfully.',
        user: this.transformUserData(user),
        loginPassword: passwords.loginPassword,
        masterPassword: passwords.masterPassword,
      };
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      logger.error('User signup error', new Error(message), { 
        email: data.email,
        errorMessage: message
      });
      return {
        success: false,
        message: 'Account creation failed',
        error: message,
      };
    }
  }

  async login(data: LoginRequest): Promise<AuthResponse> {
    try {
      logger.info('User login attempt', { email: data.email });
      const result = await this.auth.api.signInEmail({ 
        body: { 
          email: data.email, 
          password: data.password 
        } 
      });
      
      if (result.error) {
        logger.error('Login failed', new Error(result.error.message), { email: data.email });
        return { 
          success: false, 
          message: result.error.message, 
          error: result.error.message 
        };
      }
      
      logger.info('Login successful', { email: data.email, userId: result.data.user.id });
      return { 
        success: true, 
        message: 'Authentication successful', 
        user: this.transformUserData(result.data.user), 
        token: result.data.session.token 
      };
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      logger.error('Login error', new Error(message), { email: data.email });
      return { 
        success: false, 
        message: 'Authentication failed', 
        error: message 
      };
    }
  }

  async logout(sessionToken: string): Promise<{ success: boolean; message: string }> {
    try {
      await this.auth.api.signOut({ 
        headers: { 
          authorization: `Bearer ${sessionToken}` 
        } 
      });
      
      logger.info('Logout completed', { sessionToken });
      return { 
        success: true, 
        message: 'Session terminated successfully' 
      };
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      logger.error('Logout error', new Error(message), { sessionToken });
      return { 
        success: false, 
        message: 'Session termination failed' 
      };
    }
  }

  async verifyEmail(token: string): Promise<AuthResponse> {
    try {
      const result = await this.auth.api.verifyEmail({ body: { token } });
      
      if (result.error) {
        logger.error('Email verification failed', new Error(result.error.message), { token });
        return { 
          success: false, 
          message: result.error.message, 
          error: result.error.message 
        };
      }
      
      logger.info('Email verified', { userId: result.data.user.id });
      return { 
        success: true, 
        message: 'Email verification successful', 
        user: this.transformUserData(result.data.user) 
      };
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      logger.error('Email verification error', new Error(message), { token });
      return { 
        success: false, 
        message: 'Email verification failed', 
        error: message 
      };
    }
  }

  async requestPasswordReset(email: string): Promise<{ success: boolean; message: string }> {
    try {
      const result = await this.auth.api.forgetPassword({ body: { email } });
      
      if (result.error) {
        logger.error('Password reset request failed', new Error(result.error.message), { email });
        return { 
          success: false, 
          message: result.error.message 
        };
      }
      
      logger.info('Password reset requested', { email });
      return { 
        success: true, 
        message: 'Password reset instructions sent' 
      };
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      logger.error('Password reset request error', new Error(message), { email });
      return { 
        success: false, 
        message: 'Password reset request failed' 
      };
    }
  }

  async resetPassword(token: string, password: string): Promise<AuthResponse> {
    try {
      const result = await this.auth.api.resetPassword({ 
        body: { 
          token, 
          password 
        } 
      });
      
      if (result.error) {
        logger.error('Password reset failed', new Error(result.error.message), { token });
        return { 
          success: false, 
          message: result.error.message, 
          error: result.error.message 
        };
      }
      
      logger.info('Password reset completed', { userId: result.data.user.id });
      return { 
        success: true, 
        message: 'Password updated successfully', 
        user: this.transformUserData(result.data.user) 
      };
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      logger.error('Password reset error', new Error(message), { token });
      return { 
        success: false, 
        message: 'Password reset failed', 
        error: message 
      };
    }
  }

  async updateProfile(userId: string, data: UpdateProfileRequest): Promise<AuthResponse> {
    try {
      const result = await this.auth.api.updateUser({ 
        body: { 
          id: userId, 
          ...data 
        } 
      });
      
      if (result.error) {
        logger.error('Profile update failed', new Error(result.error.message), { userId });
        return { 
          success: false, 
          message: result.error.message, 
          error: result.error.message 
        };
      }
      
      logger.info('Profile updated', { userId });
      return { 
        success: true, 
        message: 'Profile updated successfully', 
        user: this.transformUserData(result.data) 
      };
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      logger.error('Profile update error', new Error(message), { userId });
      return { 
        success: false, 
        message: 'Profile update failed', 
        error: message 
      };
    }
  }

  async changePassword(userId: string, data: ChangePasswordRequest): Promise<{ success: boolean; message: string }> {
    try {
      const user = await this.auth.api.getUser({ userId });
      
      if (!user || !await this.verifyPassword(data.currentPassword, user.password)) {
        return { 
          success: false, 
          message: 'Current password verification failed' 
        };
      }
      
      const hashed = await this.hashPassword(data.newPassword);
      await this.auth.api.updateUser({ 
        body: { 
          id: userId, 
          password: hashed 
        } 
      });
      
      logger.info('Password changed', { userId });
      return { 
        success: true, 
        message: 'Password updated successfully' 
      };
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      logger.error('Password change error', new Error(message), { userId });
      return { 
        success: false, 
        message: 'Password change failed' 
      };
    }
  }

  async validateSession(token: string): Promise<SessionData | null> {
    try {
      const res = await this.auth.api.getSession({ 
        headers: { 
          authorization: `Bearer ${token}` 
        } 
      });
      
      if (res.error || !res.data) return null;
      
      return { 
        userId: res.data.user.id, 
        email: res.data.user.email, 
        name: res.data.user.name, 
        sessionId: res.data.session.id 
      };
    } catch {
      return null;
    }
  }

  async verifyMasterPassword(userId: string, masterPassword: string): Promise<boolean> {
    try {
      const user = await this.db.select()
        .from(authSchema.users)
        .where(eq(authSchema.users.id, userId))
        .limit(1);
      
      if (!user[0] || !user[0].masterPassword) {
        return false;
      }
      
      return await this.verifyPassword(masterPassword, user[0].masterPassword);
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      logger.error('Master password verification error', new Error(message), { userId });
      return false;
    }
  }

  private generatePasswords(): GeneratedPasswords {
    return { 
      loginPassword: this.generateSecurePassword(12), 
      masterPassword: this.generateSecurePassword(16) 
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
      await this.mailService.sendAccountCreationEmail(
        user.email, 
        user.name, 
        passwords.loginPassword,
        passwords.masterPassword
      );
      logger.info('Welcome email dispatched', { userId: user.id, email: user.email });
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      logger.error('Failed to send welcome email', new Error(message));
    }
  }

  private async handleUserLogin(user: any, request: any): Promise<void> {
    try {
      const clientInfo = this.extractClientInfo(request);
      await this.mailService.sendLoginNotification(user.email, { 
        name: user.name, 
        loginTime: new Date().toISOString(), 
        ip: clientInfo.ip, 
        browser: clientInfo.userAgent 
      });
      logger.info('Login notification dispatched', { userId: user.id, email: user.email, ip: clientInfo.ip });
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      logger.error('Failed to send login notification', new Error(message));
    }
  }

  private extractClientInfo(request: any): { ip: string; userAgent: string } {
    return { 
      ip: request.headers?.['x-forwarded-for'] || request.connection?.remoteAddress || 'Unknown', 
      userAgent: request.headers?.['user-agent'] || 'Unknown' 
    };
  }

  private transformUserData(user: any): UserResponse {
    return { 
      id: user.id, 
      email: user.email, 
      name: user.name, 
      emailVerified: user.emailVerified || false, 
      createdAt: user.createdAt, 
      updatedAt: user.updatedAt 
    };
  }
}
