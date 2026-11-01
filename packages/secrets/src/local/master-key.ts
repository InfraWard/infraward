import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const MASTER_KEY_ENV = 'SECRETS_LOCAL_MASTER_KEY';
export const MASTER_KEY_FILE_ENV = 'SECRETS_LOCAL_MASTER_KEY_FILE';

const KEY_BYTES = 32;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

export interface MasterKeySource {
  /** Clave en base64 (SECRETS_LOCAL_MASTER_KEY). */
  key?: string;
  /** Ruta a un fichero con la clave en base64 (SECRETS_LOCAL_MASTER_KEY_FILE), p. ej. un secret de Podman. */
  file?: string;
}

/**
 * Clave maestra del proveedor local (AES-256). Su `id` es una huella derivada de la propia
 * clave: identifica con qué clave se cifró cada secreto sin revelarla. El material de la
 * clave no sale en `toString`, `JSON.stringify` ni `console.log`.
 */
export class MasterKey {
  readonly id: string;
  readonly #bytes: Buffer;

  constructor(bytes: Buffer) {
    if (bytes.length !== KEY_BYTES) {
      throw new Error(`La clave maestra debe medir ${KEY_BYTES} bytes`);
    }
    this.#bytes = Buffer.from(bytes);
    this.id = masterKeyId(this.#bytes);
  }

  /** Material de la clave (solo para el cifrado). */
  bytes(): Buffer {
    return this.#bytes;
  }

  toString(): string {
    return `MasterKey(${this.id})`;
  }

  toJSON(): { id: string } {
    return { id: this.id };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}

/** Primeros 8 bytes (hex) de SHA-256 con separación de dominio. */
export function masterKeyId(bytes: Buffer): string {
  return createHash('sha256')
    .update('infraward-secrets-key-id:v1')
    .update(bytes)
    .digest('hex')
    .slice(0, 16);
}

/**
 * Carga y valida la clave maestra: exactamente una de las dos fuentes, base64 y 32 bytes.
 * Los errores dicen qué falla y de qué variable, nunca el valor.
 */
const MASTER_KEY_NAMES = { key: MASTER_KEY_ENV, file: MASTER_KEY_FILE_ENV };

export function loadMasterKey(
  source: MasterKeySource,
  names: { key: string; file: string } = MASTER_KEY_NAMES,
): MasterKey {
  const hasKey = source.key !== undefined && source.key !== '';
  const hasFile = source.file !== undefined && source.file !== '';
  if (hasKey && hasFile) {
    throw new Error(
      `Clave maestra de secretos: define solo una de ${names.key} o ${names.file}`,
    );
  }
  if (!hasKey && !hasFile) {
    throw new Error(
      `Clave maestra de secretos: falta ${names.key} o ${names.file} (genera una con: openssl rand -base64 32)`,
    );
  }

  let encoded: string;
  let origin: string;
  if (hasFile) {
    origin = names.file;
    try {
      encoded = readFileSync(source.file!, 'utf8').trim();
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code ?? 'error';
      throw new Error(`${origin}: no se puede leer el fichero (${code})`, {
        cause: e,
      });
    }
  } else {
    origin = names.key;
    encoded = source.key!.trim();
  }

  if (!BASE64.test(encoded) || encoded.length % 4 !== 0) {
    throw new Error(`${origin}: no es base64 válido`);
  }
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.length !== KEY_BYTES) {
    throw new Error(
      `${origin}: debe decodificar a exactamente ${KEY_BYTES} bytes (decodifica a ${bytes.length})`,
    );
  }
  return new MasterKey(bytes);
}
