import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { databaseOptions } from './database.options.js';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<EnvironmentVariables, true>) => ({
        ...databaseOptions({
          host: config.get('DATABASE_HOST', { infer: true }),
          port: config.get('DATABASE_PORT', { infer: true }),
          username: config.get('DATABASE_USER', { infer: true }),
          password: config.get('DATABASE_PASSWORD', { infer: true }),
          database: config.get('DATABASE_NAME', { infer: true }),
        }),
        // La API aplica las migraciones pendientes al arrancar.
        migrationsRun: true,
      }),
    }),
  ],
})
export class DatabaseModule {}
