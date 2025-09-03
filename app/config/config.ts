import dotenv from 'dotenv';
dotenv.config();

export const config = {
  port: process.env.PORT,
  nodeEnv: process.env.NODE_ENV,
  
  database: {
    host: process.env.PROD_DB_HOST,
    port: Number(process.env.PROD_DB_PORT),
    user: process.env.PROD_DB_USER,
    password: process.env.PROD_DB_PASSWORD,
    name: process.env.PROD_DB_NAME,
  },
  
  redis: {
    url: process.env.REDIS_URL,
    host: process.env.REDIS_HOST,
    port: Number(process.env.REDIS_PORT),
    password: process.env.REDIS_PASSWORD,
    db: Number(process.env.REDIS_DB),
  },
  
  jwt: {
    secret: process.env.JWT_SECRET,
  },
};