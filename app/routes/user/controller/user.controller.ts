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

// OTP Login Endpoints
router.post('/send-login-otp', async (req, res) => {
  try {
    const { email } = req.body || {};

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    const result = await userService.sendLoginOTP(email);

    logger.http('Login OTP sent', {
      email,
      success: true,
      ip: req.ip
    });

    res.status(200).json({
      success: true,
      message: 'OTP sent to your email address',
      data: result
    });
  } catch (error: any) {
    logger.error('Send login OTP error', error, { ip: req.ip });
    res.status(500).json({
      success: false,
      message: 'Failed to send OTP'
    });
  }
});

const otpVerificationCache = new Map<string, number>();
const CACHE_DURATION = 5000; // 5 seconds

router.post('/verify-login-otp', async (req, res) => {
  try {
    const { email, otp } = req.body || {};

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: 'Email and OTP are required'
      });
    }

    const requestKey = `${email}:${otp}:${req.ip}`;
    const now = Date.now();
    
    const lastRequest = otpVerificationCache.get(requestKey);
    if (lastRequest && (now - lastRequest) < CACHE_DURATION) {
      return res.status(429).json({
        success: false,
        message: 'Please wait before retrying'
      });
    }
    
    otpVerificationCache.set(requestKey, now);
    
    for (const [key, timestamp] of otpVerificationCache.entries()) {
      if (now - timestamp > CACHE_DURATION) {
        otpVerificationCache.delete(key);
      }
    }

    const result = await userService.verifyLoginOTP(email, otp, req);

    logger.info('OTP verification result structure', { 
      email, 
      hasResult: !!result,
      hasData: !!result?.data,
      hasSession: !!result?.session,
      hasUser: !!result?.user,
      hasToken: !!result?.token,
      hasDataSession: !!result?.data?.session,
      hasDataUser: !!result?.data?.user,
      keys: result ? Object.keys(result) : [],
      dataKeys: result?.data ? Object.keys(result.data) : []
    });

    if ((result.token && result.user) || (result.data?.session && result.data?.user)) {
      const sessionToken = result.token || result.data?.session?.token;
      const userData = result.user || result.data?.user;
      
      logger.http('OTP Login successful', {
        email,
        userId: userData?.id,
        ip: req.ip
      });

      res.status(200).json({
        success: true,
        message: 'Login successful',
        data: {
          user: userData,
          token: sessionToken
        }
      });
    } else {
      logger.http('OTP Login failed', {
        email,
        ip: req.ip
      });

      res.status(401).json({
        success: false,
        message: 'Invalid OTP or expired'
      });
    }
  } catch (error: any) {
    logger.error('Verify login OTP error', error, { ip: req.ip });
    res.status(500).json({
      success: false,
      message: 'Failed to verify OTP'
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
