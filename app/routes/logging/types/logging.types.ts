export interface LogEntry {
  id: string;
  userId: string;
  event: LogEventType;
  details: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
  timestamp: Date;
}

export interface LoginLogEntry {
  userId: string;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  timestamp: Date;
}

export interface PasswordResetLogEntry {
  userId: string;
  ipAddress: string;
  userAgent?: string;
  action: 'request' | 'complete' | 'failed';
  timestamp: Date;
}

export interface GetLogsRequest {
  userId?: string;
  eventType?: LogEventType;
  startDate?: Date;
  endDate?: Date;
  limit?: number;
  offset?: number;
}

export interface GetLogsResponse {
  success: boolean;
  logs: LogEntry[];
  total: number;
  message: string;
  error?: string;
}

export interface LogUserActivityRequest {
  userId: string;
  event: LogEventType;
  details?: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
}

export interface LogUserActivityResponse {
  success: boolean;
  logId?: string;
  message: string;
  error?: string;
}

export interface GetLastLoginRequest {
  userId: string;
}

export interface GetLastLoginResponse {
  success: boolean;
  lastLogin?: {
    timestamp: Date;
    ipAddress: string;
    userAgent: string;
  };
  message: string;
  error?: string;
}

export interface GetPasswordResetHistoryRequest {
  userId: string;
  limit?: number;
}

export interface GetPasswordResetHistoryResponse {
  success: boolean;
  resets: PasswordResetLogEntry[];
  message: string;
  error?: string;
}

export type LogEventType = 
  | 'login_success'
  | 'login_failed'
  | 'logout'
  | 'password_reset_request'
  | 'password_reset_complete'
  | 'password_reset_failed'
  | 'account_created'
  | 'email_verified'
  | 'profile_updated'
  | 'password_changed';

export interface LoggingConfig {
  enabledEvents: LogEventType[];
  retentionDays: number;
  maxEntriesPerUser: number;
}
