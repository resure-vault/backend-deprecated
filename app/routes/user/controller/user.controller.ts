import express from 'express';
import { UserService } from '../service/user.service';
import { logger } from '../../../common/logger';
import { authMiddleware } from '../middleware/auth.middleware';

const router = express.Router();
let userService: UserService;

export const initUserController = (db: any): void => {
  userService = new UserService(db);
};

router.use(express.json({ limit: '50mb' }));
router.use(express.urlencoded({ extended: true, limit: '50mb' }));

router.use((req, res, next) => {
  logger.debug('User API request', {
    method: req.method,
    path: req.path,
    body: req.body,
    ip: req.ip
  });
  next();
});

router.post('/signup', async (req, res) => {
  try {
    const { email } = req.body || {};

    if (!email) {
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

    logger.http('Signup processed', {
      email,
      success: result.success,
      ip: req.ip
    });

    res.status(statusCode).json({
      success: result.success,
      message: result.message,
      user: result.user,
      error: result.error
    });
  } catch (error: any) {
    logger.error('Signup error', error, { ip: req.ip });
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    const result = await userService.login({ email, password });
    const statusCode = result.success ? 200 : 401;

    logger.http('Login processed', {
      email,
      success: result.success,
      ip: req.ip
    });

    res.status(statusCode).json(result);
  } catch (error: any) {
    logger.error('Login error', error, { ip: req.ip });
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

router.post('/verify-master-password', authMiddleware, async (req, res) => {
  try {
    const { masterPassword } = req.body || {};

    if (!masterPassword) {
      return res.status(400).json({
        success: false,
        message: 'Master password is required'
      });
    }

    const isValid = await userService.verifyMasterPassword(req.user!.userId, masterPassword);

    res.json({
      success: true,
      valid: isValid,
      message: isValid ? 'Master password verified' : 'Invalid master password'
    });
  } catch (error: any) {
    logger.error('Master password verification error', error, { ip: req.ip });
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
    res.json(result);
  } catch (error: any) {
    logger.error('Logout error', error, { ip: req.ip });
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

router.post('/verify-email', async (req, res) => {
  try {
    const { token } = req.body || {};

    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'Verification token is required'
      });
    }

    const result = await userService.verifyEmail(token);
    const statusCode = result.success ? 200 : 400;

    res.status(statusCode).json(result);
  } catch (error: any) {
    logger.error('Email verification error', error, { ip: req.ip });
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body || {};

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    const result = await userService.requestPasswordReset(email);
    res.json(result);
  } catch (error: any) {
    logger.error('Password reset request error', error, { ip: req.ip });
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

router.post('/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body || {};

    if (!token || !password) {
      return res.status(400).json({
        success: false,
        message: 'Token and password are required'
      });
    }

    const result = await userService.resetPassword(token, password);
    const statusCode = result.success ? 200 : 400;

    res.status(statusCode).json(result);
  } catch (error: any) {
    logger.error('Password reset error', error, { ip: req.ip });
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

router.put('/profile', authMiddleware, async (req, res) => {
  try {
    const { name } = req.body || {};

    const result = await userService.updateProfile(req.user!.userId, { name });
    const statusCode = result.success ? 200 : 400;

    res.status(statusCode).json(result);
  } catch (error: any) {
    logger.error('Profile update error', error, { ip: req.ip });
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

router.put('/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};

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
    res.status(statusCode).json(result);
  } catch (error: any) {
    logger.error('Password change error', error, { ip: req.ip });
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

router.get('/profile', authMiddleware, async (req, res) => {
  try {
    res.json({
      success: true,
      user: {
        id: req.user!.userId,
        email: req.user!.email,
        name: req.user!.name
      }
    });
  } catch (error: any) {
    logger.error('Profile fetch error', error, { ip: req.ip });
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
