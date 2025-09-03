import { PostgresService } from './postgres/postgres.service';
import { RedisService } from './redis/redis.service';

export class DatabaseService {
  private postgres: PostgresService;
  private redis: RedisService;

  constructor() {
    this.postgres = PostgresService.getInstance();
    this.redis = RedisService.getInstance();
  }

  async initialize(): Promise<void> {
    console.log('Initializing database connections...');

    try {
      await this.redis.connect();
      await this.redis.testConnection();

      await this.postgres.testConnection();

      console.log('All database connections initialized successfully');
    } catch (error) {
      console.error('Database initialization failed:', error);
      throw error;
    }
  }

  getPostgres(): PostgresService {
    return this.postgres;
  }

  getRedis(): RedisService {
    return this.redis;
  }

  async close(): Promise<void> {
    await Promise.all([
      this.postgres.close(),
      this.redis.close(),
    ]);
    console.log('All database connections closed');
  }
}
