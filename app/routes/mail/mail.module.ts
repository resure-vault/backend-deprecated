import express from 'express';
import { MailService } from './service/mail.service';
import mailController from './controllers/mail.controller';

export class MailModule {
  private mailService: MailService;

  constructor() {
    this.mailService = MailService.getInstance();
  }

  getService(): MailService {
    return this.mailService;
  }

  getRouter(): express.Router {
    return mailController;
  }
}

export { MailService } from './service/mail.service';
export * from './types/mail.types';
