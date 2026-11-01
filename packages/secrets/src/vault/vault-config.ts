import type { DataSource } from 'typeorm';
import { loadMasterKey, type MasterKeySource } from '../local/master-key.js';
import {
  loadOpenBaoConfig,
  OPENBAO_ENV,
  type OpenBaoSource,
} from '../openbao/openbao-config.js';
import { LocalVaultStore, TypeOrmVaultRowStore } from './local-vault.store.js';
import { OpenBaoVaultStore } from './openbao-vault.store.js';
import {
  VAULT_DEFAULT_MAX_VERSIONS,
  VAULT_MAX_VERSIONS_LIMIT,
  type VaultStore,
} from './vault-store.js';

/** Variables de la caja fuerte. Solo las lee la API: el worker no declara ninguna. */
export const VAULT_ENV = {
  provider: 'VAULT_PROVIDER',
  maxVersions: 'VAULT_MAX_VERSIONS',
  localKey: 'VAULT_LOCAL_MASTER_KEY',
  localKeyFile: 'VAULT_LOCAL_MASTER_KEY_FILE',
  roleId: 'VAULT_OPENBAO_ROLE_ID',
  secretId: 'VAULT_OPENBAO_SECRET_ID',
  secretIdFile: 'VAULT_OPENBAO_SECRET_ID_FILE',
  kvPrefix: 'VAULT_OPENBAO_KV_PREFIX',
} as const;

export const VAULT_STORE_KINDS = ['none', 'local', 'openbao'] as const;
export type VaultStoreKind = (typeof VAULT_STORE_KINDS)[number];

/** Prefijo KV por defecto de la caja fuerte (fuera del de la app, `infraward/`). */
export const VAULT_DEFAULT_KV_PREFIX = 'infraward-vault';

export interface VaultSource {
  kind: VaultStoreKind;
  maxVersions?: number;
  /** Clave de la caja fuerte (VAULT_LOCAL_MASTER_KEY[_FILE]). */
  localKey?: MasterKeySource;
  /** Clave del proveedor `local` de la app, si la hay: la de la caja fuerte debe ser otra. */
  appLocalKey?: MasterKeySource;
  /**
   * OpenBao: dirección, mounts y tiempo de espera son los de la app (OPENBAO_*); la AppRole y el
   * prefijo, los de la caja fuerte (VAULT_OPENBAO_*).
   */
  openbao?: OpenBaoSource;
  /** AppRole y prefijo de la app, para comprobar que la caja fuerte no los comparte. */
  appOpenbao?: { roleId?: string; kvPrefix?: string };
}

const OPENBAO_NAMES = {
  ...OPENBAO_ENV,
  roleId: VAULT_ENV.roleId,
  secretId: VAULT_ENV.secretId,
  secretIdFile: VAULT_ENV.secretIdFile,
  kvPrefix: VAULT_ENV.kvPrefix,
};

/**
 * Crea el almacén de la caja fuerte (null con `none`). Se niega a arrancar si comparte la clave
 * maestra, la AppRole o el prefijo con la app: el worker tiene esos, y entonces podría leerla.
 * Los errores nombran la variable, nunca su valor.
 */
export function createVaultStore(
  source: VaultSource,
  getDataSource: () => DataSource,
): VaultStore | null {
  if (source.kind === 'none') return null;
  const maxVersions = source.maxVersions ?? VAULT_DEFAULT_MAX_VERSIONS;
  if (
    !Number.isInteger(maxVersions) ||
    maxVersions < 1 ||
    maxVersions > VAULT_MAX_VERSIONS_LIMIT
  ) {
    throw new Error(`${VAULT_ENV.maxVersions}: entre 1 y ${VAULT_MAX_VERSIONS_LIMIT}`);
  }

  if (source.kind === 'local') {
    const key = loadMasterKey(source.localKey ?? {}, {
      key: VAULT_ENV.localKey,
      file: VAULT_ENV.localKeyFile,
    });
    const appKey = source.appLocalKey;
    if (appKey && (appKey.key || appKey.file)) {
      if (loadMasterKey(appKey).id === key.id) {
        throw new Error(
          `${VAULT_ENV.localKeyFile}: la clave de la caja fuerte debe ser distinta de la de SECRETS_LOCAL_MASTER_KEY (el worker tiene esa)`,
        );
      }
    }
    return new LocalVaultStore(new TypeOrmVaultRowStore(getDataSource), key, maxVersions);
  }

  const config = loadOpenBaoConfig(
    {
      ...source.openbao,
      kvPrefix: source.openbao?.kvPrefix ?? VAULT_DEFAULT_KV_PREFIX,
    },
    OPENBAO_NAMES,
  );
  if (config.kvPrefix === '') {
    throw new Error(`${VAULT_ENV.kvPrefix}: no puede estar vacío`);
  }
  const appPrefix = (source.appOpenbao?.kvPrefix ?? 'infraward')
    .trim()
    .replace(/^\/+|\/+$/g, '');
  const nested = (a: string, b: string) => a === b || a.startsWith(`${b}/`);
  if (
    appPrefix === '' ||
    nested(config.kvPrefix, appPrefix) ||
    nested(appPrefix, config.kvPrefix)
  ) {
    throw new Error(
      `${VAULT_ENV.kvPrefix}: debe quedar fuera del prefijo de la app (OPENBAO_KV_PREFIX), que también lee el worker`,
    );
  }
  if (source.appOpenbao?.roleId?.trim() === config.credentials.roleId) {
    throw new Error(
      `${VAULT_ENV.roleId}: la caja fuerte necesita su propia AppRole (infraward-vault), no la de la app`,
    );
  }
  return new OpenBaoVaultStore(config, maxVersions);
}
