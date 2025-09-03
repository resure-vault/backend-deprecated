import type { Request, Response, NextFunction } from 'express';
import { UserService } from '../service/user.service';
import { logger } from '../../../common/logger';

declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string;
        email: string;
        name: string;
        sessionId: string;
      };
    }
  }
}

let userService: UserService;

export const initAuthMiddleware = (db: any): void => {
  userService = new UserService(db);
};

export const authMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      logger.warn('Authentication header missing or invalid', { 
        ip: req.ip,
        path: req.path 
      });
      res.status(401).json({ 
        success: false, 
        message: 'Access token required' 
      });
      return;
    }

    const token = authHeader.substring(7);
    const sessionData = await userService.validateSession(token);
    
    if (!sessionData) {
      logger.warn('Session token validation failed', { 
        ip: req.ip,
        path: req.path 
      });
      res.status(401).json({ 
        success: false, 
        message: 'Invalid or expired token' 
      });
      return;
    }

    req.user = sessionData;
    
    logger.debug('User authentication successful', {
      userId: sessionData.userId,
      email: sessionData.email,
      ip: req.ip,
      path: req.path
    });

    next();
  } catch (error: any) {
    logger.error('Authentication middleware error', error, { 
      ip: req.ip,
      path: req.path 
    });
    res.status(500).json({ 
      success: false, 
      message: 'Authentication error' 
    });
  }
};
