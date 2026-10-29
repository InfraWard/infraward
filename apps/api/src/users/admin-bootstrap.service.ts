import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { isUniqueViolation } from '../database/pg-errors.js';
import { UsersService } from './users.service.js';

/** Crea el administrador inicial desde ADMIN_EMAIL/ADMIN_PASSWORD si aún no hay usuarios. */
@Injectable()
export class AdminBootstrapService implements OnApplicationBootstrap {
  private readonly logger = new Logger(AdminBootstrapService.name);

  constructor(
    private readonly users: UsersService,
    private readonly config: ConfigService<EnvironmentVariables, true>,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    const email = this.config.get('ADMIN_EMAIL', { infer: true });
    const password = this.config.get('ADMIN_PASSWORD', { infer: true });
    if ((await this.users.count()) > 0) return;
    if (!email || !password) {
      this.logger.warn(
        'No hay usuarios: define ADMIN_EMAIL y ADMIN_PASSWORD para crear el administrador inicial',
      );
      return;
    }
    try {
      const admin = await this.users.create(email, password, 'admin');
      this.logger.log(`Administrador inicial creado: ${admin.email}`);
    } catch (error) {
      // Otra réplica de la API lo ha creado entre el count() y el insert.
      if (isUniqueViolation(error)) return;
      throw error;
    }
  }
}
