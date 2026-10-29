import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DOMAIN_ENTITIES } from '@infraward/domain';
import { SECRETS_ENTITIES } from '@infraward/secrets';
import type { EnvironmentVariables } from './config/env.validation.js';

/** Conexión con PostgreSQL. El esquema lo gestiona la API con migraciones: aquí nunca se toca. */
@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<EnvironmentVariables, true>) => ({
        type: 'postgres',
        host: config.get('DATABASE_HOST', { infer: true }),
        port: config.get('DATABASE_PORT', { infer: true }),
        username: config.get('DATABASE_USER', { infer: true }),
        password: config.get('DATABASE_PASSWORD', { infer: true }),
        database: config.get('DATABASE_NAME', { infer: true }),
        entities: [...DOMAIN_ENTITIES, ...SECRETS_ENTITIES],
        synchronize: false,
        migrationsRun: false,
        logging: ['error', 'warn'],
      }),
    }),
  ],
})
export class DatabaseModule {}
