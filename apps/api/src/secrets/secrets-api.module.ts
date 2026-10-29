import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { openBaoSourceFromEnv, SecretsModule } from '@infraward/secrets';
import {
  secretsProviders,
  type EnvironmentVariables,
} from '../config/env.validation.js';
import { SecretsController } from './secrets.controller.js';
import { SshCaTrustService } from './ssh-ca-trust.service.js';

/** SecretsService con los proveedores del entorno (también lo usa el CLI `secrets:put`). */
export const apiSecretsModule = SecretsModule.forRoot({
  inject: [ConfigService],
  useFactory: (config: ConfigService<EnvironmentVariables, true>) => ({
    enabled: secretsProviders(config.get('SECRETS_PROVIDERS', { infer: true })),
    local: {
      key: config.get('SECRETS_LOCAL_MASTER_KEY', { infer: true }),
      file: config.get('SECRETS_LOCAL_MASTER_KEY_FILE', { infer: true }),
    },
    openbao: openBaoSourceFromEnv((name) =>
      config.get(name as keyof EnvironmentVariables, { infer: true }),
    ),
    cacheTtlSeconds: config.get('SECRETS_CACHE_TTL', { infer: true }),
  }),
});

/**
 * Secretos en la API: SecretsService global (para el enrolamiento), endpoints de consulta y las
 * CA SSH vigentes (para el aviso «CA SSH desactualizada»).
 */
@Global()
@Module({
  imports: [apiSecretsModule],
  controllers: [SecretsController],
  providers: [SshCaTrustService],
  exports: [SshCaTrustService],
})
export class SecretsApiModule {}
