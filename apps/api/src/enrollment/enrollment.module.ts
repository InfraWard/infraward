import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { SessionsModule } from '../auth/sessions.module.js';
import { InventoryModule } from '../inventory/inventory.module.js';
import { JobsModule } from '../jobs/jobs.module.js';
import { ProjectsModule } from '../projects/projects.module.js';
import { EnrollController } from './enroll.controller.js';
import { EnrollmentController } from './enrollment.controller.js';
import { EnrollmentProgressService } from './enrollment-progress.service.js';
import { EnrollmentService } from './enrollment.service.js';
import { EnrollScriptTemplate } from './script-template.js';

@Module({
  imports: [JobsModule, SessionsModule, InventoryModule, ProjectsModule],
  controllers: [EnrollmentController, EnrollController],
  providers: [
    EnrollmentService,
    EnrollmentProgressService,
    {
      // Se carga al arrancar: sin plantilla válida, la API no inicia.
      provide: EnrollScriptTemplate,
      inject: [ConfigService],
      useFactory: (config: ConfigService<EnvironmentVariables, true>) =>
        EnrollScriptTemplate.load(
          config.get('ENROLL_SCRIPT_TEMPLATE', { infer: true }) || undefined,
        ),
    },
  ],
})
export class EnrollmentModule {}
