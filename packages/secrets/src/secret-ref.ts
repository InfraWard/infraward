import { SECRET_REF_PREFIX } from '@infraward/shared-types';
import { InvalidSecretRefError } from './errors.js';

export interface SecretRef {
  provider: string;
  path: string;
  field?: string;
}

const PROVIDER = /^[a-z][a-z0-9-]*$/;
const SEGMENT = /^[A-Za-z0-9._-]+$/;
const FIELD = /^[A-Za-z0-9._-]+$/;
const MAX_LENGTH = 1024;

/**
 * Valida y descompone `secret://<proveedor>/<ruta>#<campo>` (campo opcional).
 * La ruta son segmentos `[A-Za-z0-9._-]` separados por `/`, sin vacíos, `.` ni `..`.
 */
export function parseSecretRef(ref: string): SecretRef {
  if (typeof ref !== 'string' || ref.length > MAX_LENGTH) {
    throw new InvalidSecretRefError(
      `debe ser un texto de hasta ${MAX_LENGTH} caracteres`,
    );
  }
  if (!ref.startsWith(SECRET_REF_PREFIX)) {
    throw new InvalidSecretRefError(`debe empezar por ${SECRET_REF_PREFIX}`);
  }
  const rest = ref.slice(SECRET_REF_PREFIX.length);
  const hash = rest.indexOf('#');
  const location = hash === -1 ? rest : rest.slice(0, hash);
  const field = hash === -1 ? undefined : rest.slice(hash + 1);

  const slash = location.indexOf('/');
  if (slash === -1) {
    throw new InvalidSecretRefError(
      'falta la ruta (secret://<proveedor>/<ruta>)',
    );
  }
  const provider = location.slice(0, slash);
  const path = location.slice(slash + 1);

  if (!PROVIDER.test(provider)) {
    throw new InvalidSecretRefError(
      'el proveedor solo admite minúsculas, números y guiones y empieza por letra',
    );
  }
  const segments = path.split('/');
  if (segments.some((s) => !SEGMENT.test(s) || s === '.' || s === '..')) {
    throw new InvalidSecretRefError(
      'la ruta son segmentos [A-Za-z0-9._-] separados por /, sin vacíos, . ni ..',
    );
  }
  if (field !== undefined && !FIELD.test(field)) {
    throw new InvalidSecretRefError('el campo solo admite [A-Za-z0-9._-]');
  }
  return field === undefined ? { provider, path } : { provider, path, field };
}

/** Construye la referencia canónica (y la valida). */
export function formatSecretRef({ provider, path, field }: SecretRef): string {
  const ref = `${SECRET_REF_PREFIX}${provider}/${path}${field === undefined ? '' : `#${field}`}`;
  parseSecretRef(ref);
  return ref;
}
