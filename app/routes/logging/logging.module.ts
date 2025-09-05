import express from 'express';
import { LoggingService } from './service/logging.service';
import loggingController, { initLoggingController } from './controllers/logging.controller';

export class LoggingModule {
  private loggingService: LoggingService;

  constructor(db: any) {
    this.loggingService = LoggingService.getInstance(db);
    
    initLoggingController(db);
  }

  getService(): LoggingService {
    return this.loggingService;
  }

  getRouter(): express.Router {
    return loggingController;
  }
}

export { LoggingService } from './service/logging.service';
export * from './types/logging.types';
