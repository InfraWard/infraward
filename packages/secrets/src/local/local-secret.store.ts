import type { DataSource } from 'typeorm';
import { LocalSecret } from './local-secret.entity.js';

export interface EncryptedSecret {
  path: string;
  keyId: string;
  iv: Buffer;
  ciphertext: Buffer;
  authTag: Buffer;
}

/** Almacén del texto cifrado del proveedor local. */
export interface LocalSecretStore {
  find(path: string): Promise<EncryptedSecret | null>;
  upsert(secret: EncryptedSecret): Promise<void>;
  /** Devuelve si existía. */
  delete(path: string): Promise<boolean>;
  ping(): Promise<void>;
}

/**
 * Almacén en PostgreSQL (tabla local_secrets). El DataSource se obtiene al usarlo: con
 * `TypeOrmModule.forRootAsync` aún no existe cuando se construyen los proveedores.
 */
export class TypeOrmLocalSecretStore implements LocalSecretStore {
  constructor(private readonly getDataSource: () => DataSource) {}

  private get dataSource(): DataSource {
    return this.getDataSource();
  }

  async find(path: string): Promise<EncryptedSecret | null> {
    const row = await this.dataSource
      .getRepository(LocalSecret)
      .findOneBy({ path });
    return row
      ? {
          path: row.path,
          keyId: row.keyId,
          iv: row.iv,
          ciphertext: row.ciphertext,
          authTag: row.authTag,
        }
      : null;
  }

  async upsert(secret: EncryptedSecret): Promise<void> {
    await this.dataSource
      .getRepository(LocalSecret)
      .upsert(secret, { conflictPaths: ['path'] });
  }

  async delete(path: string): Promise<boolean> {
    const result = await this.dataSource
      .getRepository(LocalSecret)
      .delete({ path });
    return (result.affected ?? 0) > 0;
  }

  async ping(): Promise<void> {
    await this.dataSource.query('SELECT 1 FROM local_secrets LIMIT 1');
  }
}
