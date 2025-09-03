import express from 'express';
import { UserService } from './service/user.service';
import userController, { initUserController } from './controller/user.controller';
import { initAuthMiddleware } from './middleware/auth.middleware';

export class UserModule {
  private userService: UserService;

  constructor(db: any) {
    this.userService = new UserService(db);
    
    // Initialize controller and middleware with database
    initUserController(db);
    initAuthMiddleware(db);
  }

  getService(): UserService {
    return this.userService;
  }

  getRouter(): express.Router {
    return userController;
  }
}

export { UserService } from './service/user.service';
export * from './types/user.types';
export { authMiddleware } from './middleware/auth.middleware';
