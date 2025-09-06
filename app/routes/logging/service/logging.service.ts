import { desc, eq, and, gte, lte, count } from 'drizzle-orm';
import { logger } from '../../../common/logger';
import { getErrorMessage } from '../../../utils/error';
import * as schema from '../../../microservices/schema/schema';
import type {
  LogEntry,
  LoginLogEntry,
  PasswordResetLogEntry,
  GetLogsRequest,
  GetLogsResponse,
  LogUserActivityRequest,
  LogUserActivityResponse,
  GetLastLoginRequest,
  GetLastLoginResponse,
  GetPasswordResetHistoryRequest,
  GetPasswordResetHistoryResponse,
  LogEventType,
  LoggingConfig
} from '../types/logging.types';

export class LoggingService {
  private static instance: LoggingService | null = null;
  private db: any;
  private config: LoggingConfig;

  constructor(db: any) {
    this.db = db;
    this.config = {
      enabledEvents: [
        'login_success',
        'login_failed',
        'logout',
        'password_reset_request',
        'password_reset_complete',
        'password_reset_failed',
        'account_created',
        'email_verified',
        'profile_updated',
        'password_changed'
      ],
      retentionDays: 90,
      maxEntriesPerUser: 1000
    };
  }

  static getInstance(db?: any): LoggingService {
    if (!LoggingService.instance && db) {
      LoggingService.instance = new LoggingService(db);
    }
    if (!LoggingService.instance) {
      throw new Error('LoggingService not initialized with database');
    }
    return LoggingService.instance;
  }

  async logUserActivity(request: LogUserActivityRequest): Promise<LogUserActivityResponse> {
    try {
      if (!this.config.enabledEvents.includes(request.event)) {
        return {
          success: false,
          message: `Event type ${request.event} is not enabled`,
          error: 'Event not enabled'
        };
      }

      const logEntry = {
        userId: request.userId,
        event: request.event,
        details: JSON.stringify(request.details || {}),
        ipAddress: request.ipAddress,
        userAgent: request.userAgent
      };

      const result = await this.db.insert(schema.userLogs).values(logEntry).returning();

      logger.info(`User activity logged: ${request.event} for user ${request.userId}`);

      return {
        success: true,
        logId: result[0]?.id,
        message: 'Activity logged successfully'
      };
    } catch (error) {
      const errorMessage = getErrorMessage(error);
      logger.error(`Failed to log user activity: ${errorMessage}`);
      
      return {
        success: false,
        message: 'Failed to log activity',
        error: errorMessage
      };
    }
  }

  async getLogs(request: GetLogsRequest): Promise<GetLogsResponse> {
    try {
      const conditions = [];

      if (request.userId) {
        conditions.push(eq(schema.userLogs.userId, request.userId));
      }

      if (request.eventType) {
        conditions.push(eq(schema.userLogs.event, request.eventType));
      }

      if (request.startDate) {
        conditions.push(gte(schema.userLogs.timestamp, request.startDate));
      }

      if (request.endDate) {
        conditions.push(lte(schema.userLogs.timestamp, request.endDate));
      }

      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

      const totalResult = await this.db
        .select({ count: count() })
        .from(schema.userLogs)
        .where(whereClause);

      const total = totalResult[0]?.count || 0;

      let query = this.db
        .select()
        .from(schema.userLogs)
        .where(whereClause)
        .orderBy(desc(schema.userLogs.timestamp));

      if (request.limit) {
        query = query.limit(request.limit);
      }

      if (request.offset) {
        query = query.offset(request.offset);
      }

      const logs = await query;

      const formattedLogs: LogEntry[] = logs.map((log: any) => ({
        id: log.id,
        userId: log.userId,
        event: log.event as LogEventType,
        details: JSON.parse(log.details || '{}'),
        ipAddress: log.ipAddress,
        userAgent: log.userAgent,
        timestamp: log.timestamp
      }));

      return {
        success: true,
        logs: formattedLogs,
        total,
        message: 'Logs retrieved successfully'
      };
    } catch (error) {
      const errorMessage = getErrorMessage(error);
      logger.error(`Failed to get logs: ${errorMessage}`);
      
      return {
        success: false,
        logs: [],
        total: 0,
        message: 'Failed to retrieve logs',
        error: errorMessage
      };
    }
  }

  async getLastLogin(request: GetLastLoginRequest): Promise<GetLastLoginResponse> {
    try {
      const lastLogin = await this.db
        .select()
        .from(schema.sessions)
        .where(eq(schema.sessions.userId, request.userId))
        .orderBy(desc(schema.sessions.createdAt))
        .limit(1);

      if (!lastLogin.length) {
        return {
          success: true,
          message: 'No login sessions found'
        };
      }

      const session = lastLogin[0];

      return {
        success: true,
        lastLogin: {
          timestamp: session.createdAt,
          ipAddress: session.ipAddress || 'Unknown',
          userAgent: session.userAgent || 'Unknown'
        },
        message: 'Last login retrieved successfully'
      };
    } catch (error) {
      const errorMessage = getErrorMessage(error);
      logger.error(`Failed to get last login: ${errorMessage}`);
      
      return {
        success: false,
        message: 'Failed to retrieve last login',
        error: errorMessage
      };
    }
  }

  async getPasswordResetHistory(request: GetPasswordResetHistoryRequest): Promise<GetPasswordResetHistoryResponse> {
    try {
      let query = this.db
        .select()
        .from(schema.userLogs)
        .where(
          and(
            eq(schema.userLogs.userId, request.userId),
            eq(schema.userLogs.event, 'password_reset_request')
          )
        )
        .orderBy(desc(schema.userLogs.timestamp));

      if (request.limit) {
        query = query.limit(request.limit);
      }

      const resetLogs = await query;

      const resets: PasswordResetLogEntry[] = resetLogs.map((log: any) => {
        const details = JSON.parse(log.details || '{}');
        return {
          userId: log.userId,
          ipAddress: log.ipAddress || 'Unknown',
          userAgent: log.userAgent,
          action: details.action || 'request',
          timestamp: log.timestamp
        };
      });

      return {
        success: true,
        resets,
        message: 'Password reset history retrieved successfully'
      };
    } catch (error) {
      const errorMessage = getErrorMessage(error);
      logger.error(`Failed to get password reset history: ${errorMessage}`);
      
      return {
        success: false,
        resets: [],
        message: 'Failed to retrieve password reset history',
        error: errorMessage
      };
    }
  }

  async logLogin(userId: string, ipAddress: string, userAgent: string, success: boolean): Promise<void> {
    const eventType: LogEventType = success ? 'login_success' : 'login_failed';
    
    await this.logUserActivity({
      userId,
      event: eventType,
      details: {
        success,
        timestamp: new Date().toISOString()
      },
      ipAddress,
      userAgent
    });
  }

  async logPasswordReset(userId: string, action: 'request' | 'complete' | 'failed', ipAddress?: string, userAgent?: string): Promise<void> {
    const eventMap = {
      'request': 'password_reset_request' as LogEventType,
      'complete': 'password_reset_complete' as LogEventType,
      'failed': 'password_reset_failed' as LogEventType
    };

    await this.logUserActivity({
      userId,
      event: eventMap[action],
      details: {
        action,
        timestamp: new Date().toISOString()
      },
      ipAddress,
      userAgent
    });
  }

  async logLogout(userId: string, ipAddress?: string, userAgent?: string): Promise<void> {
    await this.logUserActivity({
      userId,
      event: 'logout',
      details: {
        timestamp: new Date().toISOString()
      },
      ipAddress,
      userAgent
    });
  }

  async logAccountCreated(userId: string, ipAddress?: string, userAgent?: string): Promise<void> {
    await this.logUserActivity({
      userId,
      event: 'account_created',
      details: {
        timestamp: new Date().toISOString()
      },
      ipAddress,
      userAgent
    });
  }

  async logEmailVerified(userId: string, ipAddress?: string, userAgent?: string): Promise<void> {
    await this.logUserActivity({
      userId,
      event: 'email_verified',
      details: {
        timestamp: new Date().toISOString()
      },
      ipAddress,
      userAgent
    });
  }

  async logProfileUpdated(userId: string, changes: Record<string, any>, ipAddress?: string, userAgent?: string): Promise<void> {
    await this.logUserActivity({
      userId,
      event: 'profile_updated',
      details: {
        changes,
        timestamp: new Date().toISOString()
      },
      ipAddress,
      userAgent
    });
  }

  async logPasswordChanged(userId: string, ipAddress?: string, userAgent?: string): Promise<void> {
    await this.logUserActivity({
      userId,
      event: 'password_changed',
      details: {
        timestamp: new Date().toISOString()
      },
      ipAddress,
      userAgent
    });
  }

  async cleanupOldLogs(): Promise<void> {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - this.config.retentionDays);

      await this.db
        .delete(schema.userLogs)
        .where(lte(schema.userLogs.timestamp, cutoffDate));

      logger.info(`Cleaned up logs older than ${this.config.retentionDays} days`);
    } catch (error) {
      logger.error(`Failed to cleanup old logs: ${getErrorMessage(error)}`);
    }
  }

  getConfig(): LoggingConfig {
    return { ...this.config };
  }

  updateConfig(newConfig: Partial<LoggingConfig>): void {
    this.config = { ...this.config, ...newConfig };
    logger.info('Logging configuration updated');
  }
}
