import { Pool, type PoolClient } from 'pg';
import { config } from '../../config/config';

export class PostgresService {
  private static instance: PostgresService;
  private pool: Pool;

  constructor() {
    this.pool = new Pool({
      host: config.database.host,
      port: config.database.port,
      user: config.database.user,
      password: config.database.password,
      database: config.database.name,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
      ssl: config.nodeEnv === 'production' ? { rejectUnauthorized: false } : false,
    });

    this.pool.on('connect', () => {
      console.log('PostgreSQL client connected');
    });

    this.pool.on('error', (err) => {
      console.error('PostgreSQL error:', err);
    });
  }

  static getInstance(): PostgresService {
    if (!PostgresService.instance) {
      PostgresService.instance = new PostgresService();
    }
    return PostgresService.instance;
  }

  async query<T = any>(text: string, params?: any[]): Promise<T[]> {
    const client = await this.pool.connect();
    try {
      const result = await client.query(text, params);
      return result.rows;
    } finally {
      client.release();
    }
  }

  async getClient(): Promise<PoolClient> {
    return this.pool.connect();
  }

  async testConnection(): Promise<boolean> {
    try {
      await this.query('SELECT NOW()');
      console.log('PostgreSQL connection successful');
      return true;
    } catch (error) {
      console.error('PostgreSQL connection failed:', error);
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
    console.log('PostgreSQL connection closed');
  }
}
