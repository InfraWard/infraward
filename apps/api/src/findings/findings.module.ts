import { Module } from '@nestjs/common';
import { JobsModule } from '../jobs/jobs.module.js';
import { CveSearchController } from './cve-search.controller.js';
import { CveSearchService } from './cve-search.service.js';
import { FindingsController } from './findings.controller.js';
import { FindingsService } from './findings.service.js';
import { SbomsController } from './sboms.controller.js';
import { SbomsService } from './sboms.service.js';

@Module({
  imports: [JobsModule],
  controllers: [FindingsController, SbomsController, CveSearchController],
  providers: [FindingsService, SbomsService, CveSearchService],
  exports: [FindingsService],
})
export class FindingsModule {}
