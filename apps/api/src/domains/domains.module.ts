import { Module } from '@nestjs/common';
import { AssetsModule } from '../assets/assets.module.js';
import { JobsModule } from '../jobs/jobs.module.js';
import {
  AssetDomainsController,
  ConnectorsController,
  DnsChecksController,
  SettingsController,
} from './domains.controller.js';
import { DomainsService } from './domains.service.js';
import {
  NatForwardsController,
  ServicePathsController,
} from './service-paths.controller.js';
import { ServicePathsService } from './service-paths.service.js';

@Module({
  imports: [AssetsModule, JobsModule],
  controllers: [
    ConnectorsController,
    AssetDomainsController,
    DnsChecksController,
    SettingsController,
    ServicePathsController,
    NatForwardsController,
  ],
  providers: [DomainsService, ServicePathsService],
})
export class DomainsModule {}
