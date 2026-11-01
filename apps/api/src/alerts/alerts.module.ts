import { Module } from '@nestjs/common';
import { JobsModule } from '../jobs/jobs.module.js';
import { AlertsController } from './alerts.controller.js';
import { AlertsService } from './alerts.service.js';

@Module({
  imports: [JobsModule],
  controllers: [AlertsController],
  providers: [AlertsService],
})
export class AlertsModule {}
