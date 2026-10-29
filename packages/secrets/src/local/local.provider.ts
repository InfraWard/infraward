import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import {
  SecretDecryptionError,
  SecretFieldNotFoundError,
  SecretKeyMismatchError,
  SecretNotFoundError,
} from '../errors.js';
import type { SecretProvider } from '../secret-provider.js';
import type { LocalSecretStore } from './local-secret.store.js';
import type { MasterKey } from './master-key.js';

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * Datos autenticados de cada fila: ligan el texto cifrado a su ruta. Si alguien con acceso
 * a la BD intercambia filas, el descifrado falla en lugar de devolver el secreto de otra ruta.
 */
export function localSecretAad(path: string): Buffer {
  return Buffer.from(`infraward:local:v1:${path}`, 'utf8');
}

/**
 * Proveedor `local`: cada ruta guarda un objeto `{ campo: valor }` serializado y cifrado con
 * AES-256-GCM (IV aleatorio por escritura) con la clave maestra, que vive fuera de la BD.
 */
export class LocalSecretProvider implements SecretProvider {
  readonly id = 'local';

  constructor(
    private readonly store: LocalSecretStore,
    private readonly masterKey: MasterKey,
  ) {}

  async get(path: string, field?: string): Promise<string> {
    const data = await this.read(path);
    const fields = Object.keys(data);
    if (field === undefined) {
      if (fields.length !== 1) {
        throw new SecretFieldNotFoundError(this.id, path, undefined);
      }
      return data[fields[0]];
    }
    if (!Object.hasOwn(data, field)) {
      throw new SecretFieldNotFoundError(this.id, path, field);
    }
    return data[field];
  }

  async set(path: string, data: Record<string, string>): Promise<void> {
    if (
      Object.keys(data).length === 0 ||
      Object.values(data).some((v) => typeof v !== 'string')
    ) {
      throw new TypeError(
        'Un secreto es un objeto no vacío de campos de texto',
      );
    }
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(ALGORITHM, this.masterKey.bytes(), iv, {
      authTagLength: TAG_BYTES,
    });
    cipher.setAAD(localSecretAad(path));
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(data), 'utf8'),
      cipher.final(),
    ]);
    await this.store.upsert({
      path,
      keyId: this.masterKey.id,
      iv,
      ciphertext,
      authTag: cipher.getAuthTag(),
    });
  }

  async delete(path: string): Promise<boolean> {
    return this.store.delete(path);
  }

  async healthCheck(): Promise<boolean> {
    try {
      await this.store.ping();
      return true;
    } catch {
      return false;
    }
  }

  private async read(path: string): Promise<Record<string, string>> {
    const row = await this.store.find(path);
    if (!row) throw new SecretNotFoundError(this.id, path);
    if (row.keyId !== this.masterKey.id) {
      throw new SecretKeyMismatchError(
        this.id,
        path,
        row.keyId,
        this.masterKey.id,
      );
    }
    let plaintext: string;
    try {
      const decipher = createDecipheriv(
        ALGORITHM,
        this.masterKey.bytes(),
        row.iv,
        { authTagLength: TAG_BYTES },
      );
      decipher.setAAD(localSecretAad(path));
      decipher.setAuthTag(row.authTag);
      plaintext = Buffer.concat([
        decipher.update(row.ciphertext),
        decipher.final(),
      ]).toString('utf8');
    } catch {
      // El error de OpenSSL no lleva datos, pero se descarta igualmente.
      throw new SecretDecryptionError(this.id, path);
    }
    return JSON.parse(plaintext) as Record<string, string>;
  }
}
