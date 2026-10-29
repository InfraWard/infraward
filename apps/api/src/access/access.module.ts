import { Module } from '@nestjs/common';
import { ACCESS_CHECKER } from '../auth/access-checker.js';
import { AccessController } from './access.controller.js';
import { AccessService } from './access.service.js';

/** Políticas de acceso interactivo (sesión 22). `ACCESS_CHECKER` lo usa `PermissionsGuard`. */
@Module({
  controllers: [AccessController],
  providers: [AccessService, { provide: ACCESS_CHECKER, useExisting: AccessService }],
  exports: [AccessService, ACCESS_CHECKER],
})
export class AccessModule {}
