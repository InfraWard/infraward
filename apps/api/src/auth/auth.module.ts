import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerModule } from '@nestjs/throttler';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { UsersModule } from '../users/users.module.js';
import {
  ApiTokensAdminController,
  OwnApiTokensController,
} from './api-tokens.controller.js';
import { AuthController } from './auth.controller.js';
import { AuthService } from './auth.service.js';
import { CsrfGuard } from './csrf.guard.js';
import { MfaAdminController, MfaController } from './mfa/mfa.controller.js';
import { MfaService } from './mfa/mfa.service.js';
import { OidcController } from './oidc/oidc.controller.js';
import { OidcService } from './oidc/oidc.service.js';
import { OidcStateStore } from './oidc/oidc-state.store.js';
import { PermissionsGuard } from './permissions.guard.js';
import { LoginAccountLimiter } from './login-account-limiter.js';
import { RecentAuthGuard } from './recent-auth.guard.js';
import {
  RedisThrottlerStorage,
  RedisThrottlerStorageModule,
} from './redis-throttler.storage.js';
import { SessionGuard } from './session.guard.js';
import { SessionsModule } from './sessions.module.js';

@Module({
  imports: [
    UsersModule,
    SessionsModule,
    // Límites de intentos: por IP (ThrottlerGuard) y, en el login, por cuenta
    // (LoginAccountLimiter). En Redis por defecto (THROTTLE_STORAGE): los comparten las réplicas.
    RedisThrottlerStorageModule,
    ThrottlerModule.forRootAsync({
      imports: [RedisThrottlerStorageModule],
      inject: [ConfigService, RedisThrottlerStorage],
      useFactory: (
        config: ConfigService<EnvironmentVariables, true>,
        redisStorage: RedisThrottlerStorage,
      ) => {
        const ttl = config.get('LOGIN_THROTTLE_TTL', { infer: true }) * 1000;
        return {
          throttlers: [
            {
              // 'default' para cabeceras estándar (Retry-After); el guard solo se aplica al login
              // (local y OIDC) y a las rutas que verifican la contraseña actual (email y
              // contraseña propios): cada ruta cuenta por separado. Los códigos TOTP y de
              // recuperación (MfaThrottlerGuard) cuentan por usuario y juntos.
              name: 'default',
              ttl,
              blockDuration: ttl,
              limit: config.get('LOGIN_THROTTLE_LIMIT', { infer: true }),
            },
          ],
          storage:
            config.get('THROTTLE_STORAGE', { infer: true }) === 'redis'
              ? redisStorage
              : undefined,
        };
      },
    }),
  ],
  controllers: [
    AuthController,
    OidcController,
    OwnApiTokensController,
    ApiTokensAdminController,
    MfaController,
    MfaAdminController,
  ],
  providers: [
    AuthService,
    OidcService,
    OidcStateStore,
    MfaService,
    LoginAccountLimiter,
    // Orden de registro = orden de ejecución: sesión, CSRF, permisos y, por último, la
    // reautenticación reciente de las acciones sensibles.
    { provide: APP_GUARD, useClass: SessionGuard },
    { provide: APP_GUARD, useClass: CsrfGuard },
    { provide: APP_GUARD, useClass: PermissionsGuard },
    { provide: APP_GUARD, useClass: RecentAuthGuard },
  ],
})
export class AuthModule {}
