import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ApiToken } from './api-token.entity.js';
import { ApiTokensService } from './api-tokens.service.js';
import { SessionRegistry } from './session-registry.js';
import { SessionService } from './session.service.js';
import { UserSession } from './user-session.entity.js';

/**
 * Sesiones web y tokens de API (los usa la autenticación y la gestión de usuarios, que los
 * revoca).
 */
@Module({
  imports: [TypeOrmModule.forFeature([UserSession, ApiToken])],
  providers: [SessionService, SessionRegistry, ApiTokensService],
  exports: [SessionService, SessionRegistry, ApiTokensService],
})
export class SessionsModule {}
