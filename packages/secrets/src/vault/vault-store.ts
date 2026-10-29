import { InvalidSecretRefError } from '../errors.js';
import { formatSecretRef, parseSecretRef } from '../secret-ref.js';

/**
 * Almacén de la caja fuerte de credenciales (QoL-7, DESIGN §19). **No es un `SecretProvider`**:
 * no se registra en `SecretsModule` (que comparten la API y el worker) y sus referencias usan
 * proveedores (`vault-local`, `vault-openbao`) que `SecretsService` no conoce. Solo la API lo
 * crea, con su propia clave maestra o su propia AppRole de OpenBao, y solo para «Revelar».
 *
 * Cada `put` crea una versión nueva; se conservan las últimas `maxVersions`.
 */
export interface VaultStore {
  readonly provider: VaultProviderId;
  readonly maxVersions: number;
  /** Guarda el valor como versión nueva y devuelve su número. */
  put(path: string, value: string): Promise<number>;
  /** La versión indicada o la actual. `SecretNotFoundError` si no existe o ya no se conserva. */
  get(path: string, version?: number): Promise<{ value: string; version: number }>;
  /** Versiones que el almacén aún conserva (de la más reciente a la más antigua). */
  versions(path: string): Promise<VaultStoredVersion[]>;
  /** Borra la ruta con todas sus versiones. Devuelve si existía. */
  destroy(path: string): Promise<boolean>;
  healthCheck(): Promise<boolean>;
  close?(): Promise<void>;
}

export interface VaultStoredVersion {
  version: number;
  createdAt: Date | null;
}

export const VAULT_PROVIDER_IDS = ['vault-local', 'vault-openbao'] as const;
export type VaultProviderId = (typeof VAULT_PROVIDER_IDS)[number];

/** Campo del secreto dentro de la ruta (OpenBao) y de la referencia. */
export const VAULT_SECRET_FIELD = 'password';

/** Versiones que se conservan por defecto (VAULT_MAX_VERSIONS). */
export const VAULT_DEFAULT_MAX_VERSIONS = 10;
export const VAULT_MAX_VERSIONS_LIMIT = 100;

/** Ruta de una entrada: `entries/<uuid>`. */
export function vaultEntryPath(entryId: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(entryId)) {
    throw new InvalidSecretRefError('id de entrada de la caja fuerte inválido');
  }
  return `entries/${entryId.toLowerCase()}`;
}

/** Referencia que se guarda en la BD (nunca el valor). */
export function vaultSecretRef(provider: VaultProviderId, path: string): string {
  return formatSecretRef({ provider, path, field: VAULT_SECRET_FIELD });
}

/** Ruta de una referencia de la caja fuerte, comprobando que es de este almacén. */
export function vaultRefPath(ref: string, provider: VaultProviderId): string {
  const parsed = parseSecretRef(ref);
  if (parsed.provider !== provider) {
    throw new InvalidSecretRefError(
      `la referencia es del proveedor ${parsed.provider} y la caja fuerte usa ${provider}`,
    );
  }
  return parsed.path;
}
