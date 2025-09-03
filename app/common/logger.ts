import winston from 'winston';

interface LogContext {
  userId?: string;
  email?: string;
  ip?: string;
  userAgent?: string;
  requestId?: string;
  [key: string]: any;
}

class Logger {
  private logger: winston.Logger;

  constructor() {
    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
        winston.format.printf((info) => {
          const { timestamp, level, message, ...meta } = info;
          return JSON.stringify({
            timestamp,
            level,
            message,
            ...meta,
          });
        })
      ),
      defaultMeta: {
        service: 'secured-bun-api',
        environment: process.env.NODE_ENV || 'development',
      },
      transports: [
        new winston.transports.Console(),
        new winston.transports.File({ 
          filename: 'logs/error.log', 
          level: 'error' 
        }),
        new winston.transports.File({ 
          filename: 'logs/combined.log' 
        }),
      ],
    });

    this.logger.exceptions.handle(
      new winston.transports.File({ filename: 'logs/exceptions.log' })
    );
  }

  info(message: string, context?: LogContext): void {
    this.logger.info(message, context);
  }

  error(message: string, error?: Error, context?: LogContext): void {
    this.logger.error(message, {
      error: error?.message,
      stack: error?.stack,
      ...context,
    });
  }

  warn(message: string, context?: LogContext): void {
    this.logger.warn(message, context);
  }

  debug(message: string, context?: LogContext): void {
    this.logger.debug(message, context);
  }

  http(message: string, context?: LogContext): void {
    this.logger.http(message, context);
  }
}

export const logger = new Logger();
