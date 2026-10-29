import { Controller, Get } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { SERVICE_NAMES, type HealthStatus } from '@infraward/shared-types';
import { Public } from '../auth/public.decorator.js';

@ApiTags('health')
@Public()
@Controller('health')
export class HealthController {
  @Get()
  check(): HealthStatus {
    return {
      service: SERVICE_NAMES.api,
      status: 'ok',
      version: process.env.npm_package_version ?? '0.0.0',
      timestamp: new Date().toISOString(),
    };
  }
}
