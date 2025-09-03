import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema/schema';
import { PostgresService } from './postgres/postgres.service';
import { RedisService } from './redis/redis.service';
import { logger } from '../common/logger';
import { config } from '../config/config';

export class DatabaseService {
  private postgres: PostgresService;
  private redis: RedisService;
  private drizzleDb: any;
  private queryClient: postgres.Sql<{}>;

  constructor() {
    this.postgres = PostgresService.getInstance();
    this.redis = RedisService.getInstance();
    
    const connectionString = this.buildConnectionString();
    
    this.queryClient = postgres(connectionString, {
      max: 10,
      idle_timeout: 20,
      connect_timeout: 10,
    });
    
    this.drizzleDb = drizzle(this.queryClient, { schema });
  }

  private buildConnectionString(): string {
    const { host, port, user, password, name } = config.database;
    return `postgres://${user}:${password}@${host}:${port}/${name}`;
  }

  async initialize(): Promise<void> {
    logger.info('Initializing database connections...');

    try {
      await this.testDrizzleConnection();
      await this.redis.connect();
      await this.redis.testConnection();
      await this.postgres.testConnection();
      logger.info('All database connections initialized successfully');
    } catch (error) {
      logger.error('Database initialization failed', error as Error);
      throw error;
    }
  }

  private async testDrizzleConnection(): Promise<void> {
    try {
      await this.queryClient`SELECT 1 as test`;
      logger.info('Drizzle connection test successful');
    } catch (error) {
      logger.error('Drizzle connection test failed', error as Error);
      throw error;
    }
  }

  getPostgres(): PostgresService {
    return this.postgres;
  }

  getRedis(): RedisService {
    return this.redis;
  }

  getDrizzle() {
    return this.drizzleDb;
  }

  getQueryClient(): postgres.Sql<{}> {
    return this.queryClient;
  }

  async close(): Promise<void> {
    try {
      await this.queryClient.end();
      await Promise.all([
        this.postgres.close(),
        this.redis.close(),
      ]);
      logger.info('All database connections closed');
    } catch (error) {
      logger.error('Error closing database connections', error as Error);
    }
  }
}
