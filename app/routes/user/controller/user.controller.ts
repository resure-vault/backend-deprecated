import express from 'express';
import { UserService } from '../service/user.service';
import { logger } from '../../../common/logger';
import { authMiddleware } from '../middleware/auth.middleware';

const router = express.Router();
let userService: UserService;

export const initUserController = (db: any): void => {
  userService = new UserService(db);
};

router.post('/signup', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      logger.warn('Signup request missing email', { ip: req.ip });
      return res.status(400).json({ 
        success: false, 
        message: 'Email address is required' 
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email address format'
      });
    }

    const result = await userService.signup({ email });
    const statusCode = result.success ? 201 : 400;
    
    logger.http(`Signup request processed`, {
      email,
      success: result.success,
      statusCode,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    const response = {
      ...result,
      loginPassword: undefined,
      masterPassword: undefined,
    };

    res.status(statusCode).json(response);
  } catch (error: any) {
    logger.error('Signup endpoint error', error, { 
      email: req.body?.email,
      ip: req.ip 
    });
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      logger.warn('Login request missing credentials', { 
        email, 
        hasPassword: !!password,
        ip: req.ip 
      });
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
    }

    const result = await userService.login({ email, password });
    const statusCode = result.success ? 200 : 401;
    
    logger.http(`Login request processed`, {
      email,
      success: result.success,
      statusCode,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(statusCode).json(result);
  } catch (error: any) {
    logger.error('Login endpoint error', error, { 
      email: req.body?.email,
      ip: req.ip 
    });
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

router.post('/verify-master-password', authMiddleware, async (req, res) => {
  try {
    const { masterPassword } = req.body;

    if (!masterPassword) {
      return res.status(400).json({
        success: false,
        message: 'Master password is required'
      });
    }

    const isValid = await userService.verifyMasterPassword(req.user!.userId, masterPassword);

    logger.info('Master password verification processed', {
      userId: req.user!.userId,
      success: isValid,
      ip: req.ip
    });

    res.json({
      success: true,
      valid: isValid,
      message: isValid ? 'Master password verified' : 'Invalid master password'
    });
  } catch (error: any) {
    logger.error('Master password verification error', error, {
      userId: req.user?.userId,
      ip: req.ip
    });
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

router.post('/logout', authMiddleware, async (req, res) => {
  try {
    const sessionToken = req.headers.authorization?.replace('Bearer ', '');
    
    if (!sessionToken) {
      return res.status(400).json({ 
        success: false, 
        message: 'Session token is required' 
      });
    }

    const result = await userService.logout(sessionToken);
    
    logger.http('Logout request processed', {
      success: result.success,
      userId: req.user?.userId,
      ip: req.ip
    });

    res.json(result);
  } catch (error: any) {
    logger.error('Logout endpoint error', error, { 
      userId: req.user?.userId,
      ip: req.ip 
    });
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

router.post('/verify-email', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ 
        success: false, 
        message: 'Verification token is required' 
      });
    }

    const result = await userService.verifyEmail(token);
    const statusCode = result.success ? 200 : 400;
    
    logger.http(`Email verification processed`, {
      success: result.success,
      statusCode,
      ip: req.ip
    });

    res.status(statusCode).json(result);
  } catch (error: any) {
    logger.error('Email verification endpoint error', error, { ip: req.ip });
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required' 
      });
    }

    const result = await userService.requestPasswordReset(email);
    
    logger.http('Password reset requested', {
      email,
      success: result.success,
      ip: req.ip
    });

    res.json(result);
  } catch (error: any) {
    logger.error('Forgot password endpoint error', error, { 
      email: req.body?.email,
      ip: req.ip 
    });
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

router.post('/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Token and password are required' 
      });
    }

    const result = await userService.resetPassword(token, password);
    const statusCode = result.success ? 200 : 400;
    
    logger.http(`Password reset processed`, {
      success: result.success,
      statusCode,
      ip: req.ip
    });

    res.status(statusCode).json(result);
  } catch (error: any) {
    logger.error('Reset password endpoint error', error, { ip: req.ip });
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

router.put('/profile', authMiddleware, async (req, res) => {
  try {
    const { name } = req.body;

    const result = await userService.updateProfile(req.user!.userId, { name });
    const statusCode = result.success ? 200 : 400;
    
    logger.http('Profile update processed', {
      success: result.success,
      userId: req.user!.userId,
      ip: req.ip
    });

    res.status(statusCode).json(result);
  } catch (error: any) {
    logger.error('Update profile endpoint error', error, { 
      userId: req.user?.userId,
      ip: req.ip 
    });
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

router.put('/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'Current password and new password are required' 
      });
    }

    const result = await userService.changePassword(req.user!.userId, {
      currentPassword,
      newPassword
    });
    
    const statusCode = result.success ? 200 : 400;
    
    logger.http('Password change processed', {
      success: result.success,
      userId: req.user!.userId,
      ip: req.ip
    });

    res.status(statusCode).json(result);
  } catch (error: any) {
    logger.error('Change password endpoint error', error, { 
      userId: req.user?.userId,
      ip: req.ip 
    });
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

router.get('/profile', authMiddleware, async (req, res) => {
  try {
    logger.http('Profile fetch processed', {
      userId: req.user!.userId,
      ip: req.ip
    });

    res.json({
      success: true,
      user: {
        id: req.user!.userId,
        email: req.user!.email,
        name: req.user!.name
      }
    });
  } catch (error: any) {
    logger.error('Get profile endpoint error', error, { 
      userId: req.user?.userId,
      ip: req.ip 
    });
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

export default router;
