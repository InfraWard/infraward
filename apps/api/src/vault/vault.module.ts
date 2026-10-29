import {
  Inject,
  Injectable,
  Module,
  type OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ModuleRef } from '@nestjs/core';
import {
  createVaultStore,
  openBaoSourceFromEnv,
  type VaultStore,
} from '@infraward/secrets';
import { DataSource } from 'typeorm';
import {
  secretsProviders,
  type EnvironmentVariables,
} from '../config/env.validation.js';
import { VaultPurgeService } from './vault-purge.service.js';
import { VaultSettingsController, VaultController } from './vault.controller.js';
import { VaultService } from './vault.service.js';
import { VAULT_STORE } from './vault.tokens.js';

/**
 * Almacén de la caja fuerte a partir del entorno. Se niega a arrancar si comparte la clave, la
 * AppRole o el prefijo con los secretos de la app (los que también tiene el worker).
 */
export function vaultStoreFromConfig(
  config: ConfigService<EnvironmentVariables, true>,
  getDataSource: () => DataSource,
): VaultStore | null {
  const get = <K extends keyof EnvironmentVariables>(k: K) =>
    config.get(k, { infer: true });
  const kind = get('VAULT_PROVIDER');
  const app = openBaoSourceFromEnv((name) =>
    config.get(name as keyof EnvironmentVariables, { infer: true }),
  );
  const appLocal = secretsProviders(get('SECRETS_PROVIDERS')).includes('local');
  return createVaultStore(
    {
      kind,
      maxVersions: get('VAULT_MAX_VERSIONS'),
      localKey: {
        key: get('VAULT_LOCAL_MASTER_KEY'),
        file: get('VAULT_LOCAL_MASTER_KEY_FILE'),
      },
      appLocalKey: appLocal
        ? {
            key: get('SECRETS_LOCAL_MASTER_KEY'),
            file: get('SECRETS_LOCAL_MASTER_KEY_FILE'),
          }
        : undefined,
      openbao: {
        addr: app.addr,
        kvMount: app.kvMount,
        approleMount: app.approleMount,
        timeoutMs: app.timeoutMs,
        roleId: get('VAULT_OPENBAO_ROLE_ID'),
        secretId: get('VAULT_OPENBAO_SECRET_ID'),
        secretIdFile: get('VAULT_OPENBAO_SECRET_ID_FILE'),
        kvPrefix: get('VAULT_OPENBAO_KV_PREFIX'),
      },
      appOpenbao: { roleId: app.roleId, kvPrefix: app.kvPrefix },
    },
    getDataSource,
  );
}

/** Cierra el almacén (revoca el token de OpenBao) al parar la API. */
@Injectable()
class VaultStoreCloser implements OnApplicationShutdown {
  constructor(@Inject(VAULT_STORE) private readonly store: VaultStore | null) {}

  async onApplicationShutdown(): Promise<void> {
    await this.store?.close?.();
  }
}

/** Caja fuerte de credenciales (QoL-7, DESIGN §19). Solo existe en la API. */
@Module({
  controllers: [VaultController, VaultSettingsController],
  providers: [
    {
      provide: VAULT_STORE,
      inject: [ConfigService, ModuleRef],
      useFactory: (
        config: ConfigService<EnvironmentVariables, true>,
        moduleRef: ModuleRef,
      ) =>
        vaultStoreFromConfig(config, () =>
          moduleRef.get(DataSource, { strict: false }),
        ),
    },
    VaultStoreCloser,
    VaultService,
    VaultPurgeService,
  ],
  exports: [VaultService],
})
export class VaultModule {}
