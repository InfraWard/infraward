import { Module } from '@nestjs/common';
import { AssetsModule } from '../assets/assets.module.js';
import { CollectionModule } from '../collection/collection.module.js';
import { FindingsModule } from '../findings/findings.module.js';
import { InventoryModule } from '../inventory/inventory.module.js';
import { ProjectsModule } from '../projects/projects.module.js';
import { BulkController } from './bulk.controller.js';
import { BulkService } from './bulk.service.js';

@Module({
  imports: [
    AssetsModule,
    CollectionModule,
    FindingsModule,
    InventoryModule,
    ProjectsModule,
  ],
  controllers: [BulkController],
  providers: [BulkService],
})
export class BulkModule {}
