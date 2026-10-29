// DataSource para el CLI de TypeORM (migration:run, migration:revert, migration:generate).
// Uso: pnpm --filter @infraward/api migration:run (tras build). Lee el mismo .env que la API.
import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { loadEnvFiles } from '../config/env-files.js';
import { validateEnv } from '../config/env.validation.js';
import { databaseOptions } from './database.options.js';

loadEnvFiles();
const env = validateEnv(process.env);

export default new DataSource(
  databaseOptions({
    host: env.DATABASE_HOST,
    port: env.DATABASE_PORT,
    username: env.DATABASE_USER,
    password: env.DATABASE_PASSWORD,
    database: env.DATABASE_NAME,
  }),
);
