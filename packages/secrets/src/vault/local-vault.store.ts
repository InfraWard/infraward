import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { DataSource } from 'typeorm';
import {
  SecretDecryptionError,
  SecretKeyMismatchError,
  SecretNotFoundError,
} from '../errors.js';
import type { MasterKey } from '../local/master-key.js';
import { VaultLocalSecret } from './local-vault.entity.js';
import type { VaultStore, VaultStoredVersion } from './vault-store.js';

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;
const TAG_BYTES = 16;
const PROVIDER = 'vault-local';

/**
 * Datos autenticados: ligan el texto cifrado a su ruta **y su versión** (y a la caja fuerte:
 * una fila copiada de `local_secrets` no descifra aquí ni al revés).
 */
export function vaultSecretAad(path: string, version: number): Buffer {
  return Buffer.from(`infraward:vault:v1:${path}#${version}`, 'utf8');
}

export interface EncryptedVaultVersion {
  path: string;
  version: number;
  keyId: string;
  iv: Buffer;
  ciphertext: Buffer;
  authTag: Buffer;
  createdAt?: Date;
}

/** Filas del almacén local (inyectable en los tests). */
export interface VaultRowStore {
  /** La versión indicada o la más reciente. */
  find(path: string, version?: number): Promise<EncryptedVaultVersion | null>;
  list(path: string): Promise<{ version: number; createdAt: Date }[]>;
  /**
   * Inserta la versión siguiente (atómico por ruta) cifrándola con `build(version)` y borra las
   * que pasen de `keep`. Devuelve la versión nueva.
   */
  append(
    path: string,
    build: (version: number) => EncryptedVaultVersion,
    keep: number,
  ): Promise<number>;
  deleteAll(path: string): Promise<boolean>;
  ping(): Promise<void>;
}

/** Almacén local de la caja fuerte: AES-256-GCM con su propia clave maestra, versionado. */
export class LocalVaultStore implements VaultStore {
  readonly provider = PROVIDER;

  constructor(
    private readonly rows: VaultRowStore,
    private readonly masterKey: MasterKey,
    readonly maxVersions: number,
  ) {}

  put(path: string, value: string): Promise<number> {
    if (typeof value !== 'string' || value === '') {
      throw new TypeError('El secreto es un texto no vacío');
    }
    return this.rows.append(
      path,
      (version) => {
        const iv = randomBytes(IV_BYTES);
        const cipher = createCipheriv(ALGORITHM, this.masterKey.bytes(), iv, {
          authTagLength: TAG_BYTES,
        });
        cipher.setAAD(vaultSecretAad(path, version));
        const ciphertext = Buffer.concat([
          cipher.update(value, 'utf8'),
          cipher.final(),
        ]);
        return {
          path,
          version,
          keyId: this.masterKey.id,
          iv,
          ciphertext,
          authTag: cipher.getAuthTag(),
        };
      },
      this.maxVersions,
    );
  }

  async get(
    path: string,
    version?: number,
  ): Promise<{ value: string; version: number }> {
    const row = await this.rows.find(path, version);
    if (!row) throw new SecretNotFoundError(PROVIDER, path);
    if (row.keyId !== this.masterKey.id) {
      throw new SecretKeyMismatchError(PROVIDER, path, row.keyId, this.masterKey.id);
    }
    try {
      const decipher = createDecipheriv(ALGORITHM, this.masterKey.bytes(), row.iv, {
        authTagLength: TAG_BYTES,
      });
      decipher.setAAD(vaultSecretAad(path, row.version));
      decipher.setAuthTag(row.authTag);
      const value = Buffer.concat([
        decipher.update(row.ciphertext),
        decipher.final(),
      ]).toString('utf8');
      return { value, version: row.version };
    } catch {
      throw new SecretDecryptionError(PROVIDER, path);
    }
  }

  async versions(path: string): Promise<VaultStoredVersion[]> {
    return (await this.rows.list(path))
      .map((r) => ({ version: r.version, createdAt: r.createdAt }))
      .sort((a, b) => b.version - a.version);
  }

  destroy(path: string): Promise<boolean> {
    return this.rows.deleteAll(path);
  }

  async healthCheck(): Promise<boolean> {
    try {
      await this.rows.ping();
      return true;
    } catch {
      return false;
    }
  }

  toJSON(): object {
    return { provider: this.provider, key: this.masterKey.id };
  }
}

/**
 * Filas en PostgreSQL (`vault_local_secrets`). `append` bloquea la ruta con un advisory lock de
 * transacción: dos escrituras simultáneas no calculan la misma versión.
 */
export class TypeOrmVaultRowStore implements VaultRowStore {
  constructor(private readonly getDataSource: () => DataSource) {}

  private get repo() {
    return this.getDataSource().getRepository(VaultLocalSecret);
  }

  async find(path: string, version?: number): Promise<EncryptedVaultVersion | null> {
    const row =
      version === undefined
        ? await this.repo.findOne({ where: { path }, order: { version: 'DESC' } })
        : await this.repo.findOneBy({ path, version });
    return row
      ? {
          path: row.path,
          version: row.version,
          keyId: row.keyId,
          iv: row.iv,
          ciphertext: row.ciphertext,
          authTag: row.authTag,
          createdAt: row.createdAt,
        }
      : null;
  }

  async list(path: string): Promise<{ version: number; createdAt: Date }[]> {
    return this.repo.find({
      select: { version: true, createdAt: true },
      where: { path },
      order: { version: 'DESC' },
    });
  }

  append(
    path: string,
    build: (version: number) => EncryptedVaultVersion,
    keep: number,
  ): Promise<number> {
    return this.getDataSource().transaction(async (m) => {
      await m.query(`SELECT pg_advisory_xact_lock(hashtext('vault:' || $1))`, [path]);
      const [{ max }] = (await m.query(
        'SELECT COALESCE(MAX(version), 0)::int AS max FROM vault_local_secrets WHERE path = $1',
        [path],
      )) as { max: number }[];
      const version = max + 1;
      const row = build(version);
      await m.insert(VaultLocalSecret, {
        path,
        version,
        keyId: row.keyId,
        iv: row.iv,
        ciphertext: row.ciphertext,
        authTag: row.authTag,
      });
      await m.query(
        'DELETE FROM vault_local_secrets WHERE path = $1 AND version <= $2',
        [path, version - keep],
      );
      return version;
    });
  }

  async deleteAll(path: string): Promise<boolean> {
    const result = await this.repo.delete({ path });
    return (result.affected ?? 0) > 0;
  }

  async ping(): Promise<void> {
    await this.getDataSource().query('SELECT 1 FROM vault_local_secrets LIMIT 1');
  }
}
