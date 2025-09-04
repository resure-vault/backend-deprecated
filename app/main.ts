import express from 'express';
import cors from 'cors';
import { MailModule } from './routes/mail/mail.module';
import { UserModule } from './routes/user/user.module';
import { DatabaseService } from './microservices/database';
import { logger } from './common/logger';
import { config } from './config/config';

class Application {
  private readonly app: express.Application;
  private readonly databaseService: DatabaseService;
  private mailModule?: MailModule;
  private userModule?: UserModule;

  constructor() {
    this.app = express();
    this.databaseService = new DatabaseService();
  }

  private configureMiddleware(): void {
    logger.info('Configuring application middleware');
    
    this.app.use(cors({
      origin: true,
      credentials: true,
    }));
    
    this.app.use(express.json({ 
      limit: '10mb',
      strict: false
    }));
    
    this.app.use(express.urlencoded({ 
      extended: true, 
      limit: '10mb' 
    }));

    this.app.use((req, res, next) => {
      logger.debug('Request received', {
        method: req.method,
        url: req.url,
        body: req.body,
        headers: req.headers,
        ip: req.ip
      });
      next();
    });
    
    logger.info('Application middleware configured successfully');
  }

  private configureHealthCheck(): void {
    this.app.get('/health', (req, res) => {
      res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        service: 'secured-api',
        environment: config.nodeEnv,
        uptime: process.uptime(),
        memory: process.memoryUsage()
      });
    });
    logger.info('Health check endpoint configured');
  }

  private async initializeDatabase(): Promise<void> {
    logger.info('Database initialization starting');
    await this.databaseService.initialize();
    logger.info('Database initialization completed successfully');
  }

  private initializeModules(): void {
    logger.info('Application modules initialization starting');
    
    try {
      this.mailModule = new MailModule();
      logger.info('Mail service module initialized and ready');
      
      this.userModule = new UserModule(this.databaseService.getDrizzle());
      logger.info('User service module initialized with authentication');
      
      logger.info('All application modules initialized successfully');
    } catch (error) {
      logger.error('Module initialization failed', error as Error);
      throw error;
    }
  }

  private configureRoutes(): void {
    logger.info('Configuring application routes');
    
    if (this.mailModule) {
      this.app.use('/api/mail', this.mailModule.getRouter());
      logger.info('Mail API routes mounted on /api/mail');
    }
    
    if (this.userModule) {
      this.app.use('/api/auth', this.userModule.getRouter());
      logger.info('Authentication API routes mounted on /api/auth');
    }

    this.app.use((req, res) => {
      logger.warn('404 - Route not found', {
        method: req.method,
        path: req.originalUrl,
        ip: req.ip
      });
      
      res.status(404).json({
        success: false,
        message: 'Endpoint not found',
        path: req.originalUrl,
        method: req.method
      });
    });

    logger.info('Application routes configuration completed');
  }

  private setupGracefulShutdown(): void {
    const shutdown = async (signal: string): Promise<void> => {
      logger.info(`Shutdown signal received: ${signal}`, { signal });
      
      try {
        logger.info('Closing database connections');
        await this.databaseService.close();
        logger.info('Database connections closed successfully');
        
        logger.info('Graceful shutdown completed successfully');
        process.exit(0);
      } catch (error) {
        logger.error('Error during graceful shutdown', error as Error);
        process.exit(1);
      }
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGUSR2', () => shutdown('SIGUSR2'));

    logger.info('Graceful shutdown handlers registered');
  }

  private async findAvailablePort(): Promise<number> {
    const defaultPort = parseInt(config.port || '8080');
    
    for (let port = defaultPort; port < defaultPort + 10; port++) {
      try {
        await new Promise<void>((resolve, reject) => {
          const server = this.app.listen(port, () => {
            server.close();
            resolve();
          });
          server.on('error', reject);
        });
        return port;
      } catch (error) {
        continue;
      }
    }
    
    throw new Error(`No available ports found starting from ${defaultPort}`);
  }

  async start(): Promise<void> {
    try {
      logger.info('Application startup sequence initiated', {
        environment: config.nodeEnv,
        nodeVersion: process.version,
        platform: process.platform
      });

      this.configureMiddleware();
      this.configureHealthCheck();
      
      await this.initializeDatabase();
      this.initializeModules();
      this.configureRoutes();
      this.setupGracefulShutdown();

      const port = await this.findAvailablePort();
      
      const server = this.app.listen(port, () => {
        logger.info('HTTP server started and listening for connections', {
          port: port,
          environment: config.nodeEnv,
          timestamp: new Date().toISOString(),
          pid: process.pid
        });
      });

      server.on('error', (error: any) => {
        if (error.code === 'EADDRINUSE') {
          logger.error(`Port ${port} is already in use`, error);
        } else {
          logger.error('Server startup failed', error);
        }
        process.exit(1);
      });

      process.on('uncaughtException', (error) => {
        logger.error('Uncaught exception occurred', error);
        process.exit(1);
      });

      process.on('unhandledRejection', (reason, promise) => {
        logger.error('Unhandled promise rejection', new Error(String(reason)), {
          promise: promise.toString()
        });
        process.exit(1);
      });

    } catch (error) {
      logger.error('Application startup failed', error as Error);
      process.exit(1);
    }
  }
}

const application = new Application();
application.start();
