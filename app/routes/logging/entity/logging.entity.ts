export interface UserLog {
  id: string;
  userId: string;
  event: string;
  details: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
  timestamp: Date;
  createdAt: Date;
}

export interface LoginSession {
  id: string;
  userId: string;
  token: string;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
  ipAddress?: string;
  userAgent?: string;
}

export interface PasswordReset {
  id: string;
  userId: string;
  action: 'request' | 'complete' | 'failed';
  ipAddress?: string;
  userAgent?: string;
  timestamp: Date;
}
