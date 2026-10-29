import { Global, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuditController } from './audit.controller.js';
import { AuditEvent } from './audit-event.entity.js';
import { AuditService } from './audit.service.js';

/** Global: cualquier módulo con acciones relevantes las audita. */
@Global()
@Module({
  imports: [TypeOrmModule.forFeature([AuditEvent])],
  controllers: [AuditController],
  providers: [AuditService],
  exports: [AuditService],
})
export class AuditModule {}
