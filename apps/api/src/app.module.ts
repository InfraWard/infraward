import { AlertsModule } from './alerts/alerts.module.js';
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AssetsModule } from './assets/assets.module.js';
import { AuditModule } from './audit/audit.module.js';
import { AuthModule } from './auth/auth.module.js';
import { BulkModule } from './bulk/bulk.module.js';
import { CollectionModule } from './collection/collection.module.js';
import { ENV_FILES } from './config/env-files.js';
import { validateEnv } from './config/env.validation.js';
import { DashboardModule } from './dashboard/dashboard.module.js';
import { DatabaseModule } from './database/database.module.js';
import { DomainsModule } from './domains/domains.module.js';
import { EnrollmentModule } from './enrollment/enrollment.module.js';
import { ExportsModule } from './exports/exports.module.js';
import { FindingsModule } from './findings/findings.module.js';
import { HealthModule } from './health/health.module.js';
import { InventoryModule } from './inventory/inventory.module.js';
import { JobsModule } from './jobs/jobs.module.js';
import { NotificationsModule } from './notifications/notifications.module.js';
import { ProjectsModule } from './projects/projects.module.js';
import { SecretsApiModule } from './secrets/secrets-api.module.js';
import { TerminalModule } from './terminal/terminal.module.js';
import { VaultModule } from './vault/vault.module.js';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ENV_FILES,
      validate: validateEnv,
    }),
    DatabaseModule,
    AuditModule,
    AuthModule,
    AssetsModule,
    BulkModule,
    CollectionModule,
    DashboardModule,
    DomainsModule,
    EnrollmentModule,
    ExportsModule,
    FindingsModule,
    HealthModule,
    InventoryModule,
    JobsModule,
    NotificationsModule,
    ProjectsModule,
    SecretsApiModule,
    VaultModule,
    TerminalModule,
    AlertsModule,
  ],
})
export class AppModule {}
