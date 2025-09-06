import express from 'express';
import { LoggingService } from '../service/logging.service';
import { logger } from '../../../common/logger';
import { getErrorMessage } from '../../../utils/error';
import type {
  GetLogsRequest,
  LogUserActivityRequest,
  GetLastLoginRequest,
  GetPasswordResetHistoryRequest,
  LoggingConfig
} from '../types/logging.types';

let loggingService: LoggingService;

function initLoggingController(db: any) {
  loggingService = LoggingService.getInstance(db);
}

const router = express.Router();

router.get('/logs', async (req: express.Request, res: express.Response) => {
  try {
    const request: GetLogsRequest = {
      userId: req.query.userId as string,
      eventType: req.query.eventType as any,
      startDate: req.query.startDate ? new Date(req.query.startDate as string) : undefined,
      endDate: req.query.endDate ? new Date(req.query.endDate as string) : undefined,
      limit: req.query.limit ? parseInt(req.query.limit as string) : undefined,
      offset: req.query.offset ? parseInt(req.query.offset as string) : undefined
    };

    const result = await loggingService.getLogs(request);
    
    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    const errorMessage = getErrorMessage(error);
    logger.error(`Get logs error: ${errorMessage}`);
    res.status(500).json({
      success: false,
      logs: [],
      total: 0,
      message: 'Internal server error',
      error: errorMessage
    });
  }
});

router.post('/log-activity', async (req: express.Request, res: express.Response) => {
  try {
    const request: LogUserActivityRequest = {
      userId: req.body.userId,
      event: req.body.event,
      details: req.body.details,
      ipAddress: req.ip || req.body.ipAddress,
      userAgent: req.get('User-Agent') || req.body.userAgent
    };

    if (!request.userId || !request.event) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: userId and event',
        error: 'Validation error'
      });
    }

    const result = await loggingService.logUserActivity(request);
    
    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    const errorMessage = getErrorMessage(error);
    logger.error(`Log activity error: ${errorMessage}`);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: errorMessage
    });
  }
});

router.get('/last-login/:userId', async (req: express.Request, res: express.Response) => {
  try {
    const userId = req.params.userId;
    
    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'User ID is required',
        error: 'Validation error'
      });
    }

    const request: GetLastLoginRequest = { userId };
    const result = await loggingService.getLastLogin(request);
    
    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    const errorMessage = getErrorMessage(error);
    logger.error(`Get last login error: ${errorMessage}`);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: errorMessage
    });
  }
});

router.get('/password-reset-history/:userId', async (req: express.Request, res: express.Response) => {
  try {
    const userId = req.params.userId;
    
    if (!userId) {
      return res.status(400).json({
        success: false,
        resets: [],
        message: 'User ID is required',
        error: 'Validation error'
      });
    }

    const request: GetPasswordResetHistoryRequest = {
      userId,
      limit: req.query.limit ? parseInt(req.query.limit as string) : undefined
    };

    const result = await loggingService.getPasswordResetHistory(request);
    
    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    const errorMessage = getErrorMessage(error);
    logger.error(`Get password reset history error: ${errorMessage}`);
    res.status(500).json({
      success: false,
      resets: [],
      message: 'Internal server error',
      error: errorMessage
    });
  }
});

router.get('/config', async (req: express.Request, res: express.Response) => {
  try {
    const config = loggingService.getConfig();
    res.status(200).json({
      success: true,
      config,
      message: 'Configuration retrieved successfully'
    });
  } catch (error) {
    const errorMessage = getErrorMessage(error);
    logger.error(`Get config error: ${errorMessage}`);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: errorMessage
    });
  }
});

router.put('/config', async (req: express.Request, res: express.Response) => {
  try {
    const configUpdate: Partial<LoggingConfig> = req.body;

    if (configUpdate.enabledEvents && !Array.isArray(configUpdate.enabledEvents)) {
      return res.status(400).json({
        success: false,
        message: 'enabledEvents must be an array',
        error: 'Validation error'
      });
    }

    if (configUpdate.retentionDays && (typeof configUpdate.retentionDays !== 'number' || configUpdate.retentionDays < 1)) {
      return res.status(400).json({
        success: false,
        message: 'retentionDays must be a positive number',
        error: 'Validation error'
      });
    }

    if (configUpdate.maxEntriesPerUser && (typeof configUpdate.maxEntriesPerUser !== 'number' || configUpdate.maxEntriesPerUser < 1)) {
      return res.status(400).json({
        success: false,
        message: 'maxEntriesPerUser must be a positive number',
        error: 'Validation error'
      });
    }

    loggingService.updateConfig(configUpdate);
    
    res.status(200).json({
      success: true,
      config: loggingService.getConfig(),
      message: 'Configuration updated successfully'
    });
  } catch (error) {
    const errorMessage = getErrorMessage(error);
    logger.error(`Update config error: ${errorMessage}`);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: errorMessage
    });
  }
});

router.post('/cleanup', async (req: express.Request, res: express.Response) => {
  try {
    await loggingService.cleanupOldLogs();
    
    res.status(200).json({
      success: true,
      message: 'Log cleanup completed successfully'
    });
  } catch (error) {
    const errorMessage = getErrorMessage(error);
    logger.error(`Cleanup error: ${errorMessage}`);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: errorMessage
    });
  }
});

export { initLoggingController };
export default router;
