import { Module } from '@nestjs/common';
import { JobsModule } from '../jobs/jobs.module.js';
import { CollectionController } from './collection.controller.js';
import { CollectionService } from './collection.service.js';

@Module({
  imports: [JobsModule],
  controllers: [CollectionController],
  providers: [CollectionService],
  exports: [CollectionService],
})
export class CollectionModule {}
