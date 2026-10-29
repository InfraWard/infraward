import { Module } from '@nestjs/common';
import { AssetsModule } from '../assets/assets.module.js';
import { FindingsModule } from '../findings/findings.module.js';
import { ExportsController } from './exports.controller.js';
import { ExportsService } from './exports.service.js';

@Module({
  imports: [AssetsModule, FindingsModule],
  controllers: [ExportsController],
  providers: [ExportsService],
})
export class ExportsModule {}
