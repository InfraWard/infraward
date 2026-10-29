import {
  Module,
  type DynamicModule,
  type InjectionToken,
  type ModuleMetadata,
  type OptionalFactoryDependency,
} from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { DataSource } from 'typeorm';
import { TypeOrmLocalSecretStore } from './local/local-secret.store.js';
import { LocalSecretProvider } from './local/local.provider.js';
import { loadMasterKey, type MasterKeySource } from './local/master-key.js';
import {
  loadOpenBaoConfig,
  type OpenBaoSource,
} from './openbao/openbao-config.js';
import { OpenBaoSecretProvider } from './openbao/openbao.provider.js';
import { SECRET_PROVIDERS, type SecretProvider } from './secret-provider.js';
import { SECRETS_CACHE_TTL, SecretsService } from './secrets.service.js';

export interface SecretsModuleOptions {
  /** Proveedores activos, p. ej. de SECRETS_PROVIDERS=local. */
  enabled: string[];
  /** Origen de la clave maestra del proveedor local (obligatoria si `local` está activo). */
  local?: MasterKeySource;
  /** Conexión y credenciales AppRole de OpenBao (obligatorias si `openbao` está activo). */
  openbao?: OpenBaoSource;
  /** Vida de la caché en memoria, en segundos (0 = sin caché, máx. 300). */
  cacheTtlSeconds?: number;
}

export interface SecretsModuleAsyncOptions {
  imports?: ModuleMetadata['imports'];
  inject?: (InjectionToken | OptionalFactoryDependency)[];
  useFactory: (
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- como en los forRootAsync de Nest
    ...args: any[]
  ) => SecretsModuleOptions | Promise<SecretsModuleOptions>;
}

/** Crea un proveedor; puede pedir dependencias de la app (p. ej., el DataSource) al ModuleRef. */
type ProviderFactory = (
  options: SecretsModuleOptions,
  moduleRef: ModuleRef,
) => SecretProvider;

/** Proveedores conocidos. Añadir uno nuevo = implementar SecretProvider y registrarlo aquí. */
export const SECRET_PROVIDER_FACTORIES: Record<string, ProviderFactory> = {
  local: (options, moduleRef) =>
    new LocalSecretProvider(
      new TypeOrmLocalSecretStore(() =>
        moduleRef.get(DataSource, { strict: false }),
      ),
      loadMasterKey(options.local ?? {}),
    ),
  openbao: (options) =>
    new OpenBaoSecretProvider(loadOpenBaoConfig(options.openbao ?? {})),
};

export const KNOWN_SECRET_PROVIDERS = Object.keys(SECRET_PROVIDER_FACTORIES);

const SECRETS_OPTIONS = Symbol('SECRETS_OPTIONS');

/** Crea solo los proveedores habilitados; un id desconocido o repetido impide arrancar. */
export function createSecretProviders(
  options: SecretsModuleOptions,
  moduleRef: ModuleRef,
): SecretProvider[] {
  if (options.enabled.length === 0) {
    throw new Error('SECRETS_PROVIDERS: indica al menos un proveedor');
  }
  const seen = new Set<string>();
  return options.enabled.map((id) => {
    const factory = Object.hasOwn(SECRET_PROVIDER_FACTORIES, id)
      ? SECRET_PROVIDER_FACTORIES[id]
      : undefined;
    if (!factory) {
      throw new Error(
        `SECRETS_PROVIDERS: proveedor desconocido "${id}" (disponibles: ${KNOWN_SECRET_PROVIDERS.join(', ')})`,
      );
    }
    if (seen.has(id)) {
      throw new Error(`SECRETS_PROVIDERS: proveedor repetido "${id}"`);
    }
    seen.add(id);
    return factory(options, moduleRef);
  });
}

/** Módulo global de secretos: `SecretsService` resuelve referencias con los proveedores activos. */
@Module({})
export class SecretsModule {
  static forRoot(options: SecretsModuleAsyncOptions): DynamicModule {
    return {
      module: SecretsModule,
      global: true,
      imports: options.imports ?? [],
      providers: [
        {
          provide: SECRETS_OPTIONS,
          inject: options.inject ?? [],
          useFactory: options.useFactory,
        },
        {
          provide: SECRET_PROVIDERS,
          inject: [SECRETS_OPTIONS, ModuleRef],
          useFactory: createSecretProviders,
        },
        {
          provide: SECRETS_CACHE_TTL,
          inject: [SECRETS_OPTIONS],
          useFactory: (o: SecretsModuleOptions) => o.cacheTtlSeconds ?? 60,
        },
        SecretsService,
      ],
      exports: [SecretsService],
    };
  }
}
