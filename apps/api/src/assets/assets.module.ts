import { Module } from '@nestjs/common';
import {
  AssetRelationsController,
  AssetsController,
  SnapshotsController,
} from './assets.controller.js';
import { AssetsService } from './assets.service.js';
import { AssetGraphService } from './graph.service.js';

@Module({
  controllers: [
    AssetsController,
    AssetRelationsController,
    SnapshotsController,
  ],
  providers: [AssetsService, AssetGraphService],
  exports: [AssetsService],
})
export class AssetsModule {}
