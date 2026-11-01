import { Module } from '@nestjs/common';
import { QueueModule } from '../queue/queue.module.js';
import { AssetRunsController } from './asset-runs.controller.js';
import { JobEventsService } from './job-events.service.js';
import { JobRunsService } from './job-runs.service.js';
import { JobsController } from './jobs.controller.js';
import { JobsService } from './jobs.service.js';

@Module({
  imports: [QueueModule],
  controllers: [JobsController, AssetRunsController],
  providers: [JobsService, JobRunsService, JobEventsService],
  exports: [JobsService, JobRunsService, JobEventsService],
})
export class JobsModule {}
