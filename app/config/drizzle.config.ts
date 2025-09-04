import { defineConfig } from 'drizzle-kit';
import { config } from './config';

export default defineConfig({
  schema: './database/schema/schema.ts',
  out: './drizzle',
  dialect: 'postgresql',
  dbCredentials: {
    host: config.database.host!,
    port: config.database.port!,
    user: config.database.user!,
    password: config.database.password!,
    database: config.database.name!,
  },
  verbose: true,
  strict: true
});
