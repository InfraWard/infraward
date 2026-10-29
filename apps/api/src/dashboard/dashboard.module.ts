import { Module } from '@nestjs/common';
import { JobsModule } from '../jobs/jobs.module.js';
import { DashboardWidgetsController } from './dashboard-widgets.controller.js';
import { DashboardWidgetsService } from './dashboard-widgets.service.js';
import { DashboardController } from './dashboard.controller.js';
import { DashboardService } from './dashboard.service.js';
import { DashboardsController } from './dashboards.controller.js';
import { DashboardsService } from './dashboards.service.js';

@Module({
  imports: [JobsModule],
  controllers: [
    DashboardController,
    DashboardWidgetsController,
    DashboardsController,
  ],
  providers: [DashboardService, DashboardWidgetsService, DashboardsService],
})
export class DashboardModule {}
