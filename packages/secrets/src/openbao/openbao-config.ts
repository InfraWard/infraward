import { readFileSync } from 'node:fs';

export const OPENBAO_ENV = {
  addr: 'OPENBAO_ADDR',
  roleId: 'OPENBAO_ROLE_ID',
  secretId: 'OPENBAO_SECRET_ID',
  secretIdFile: 'OPENBAO_SECRET_ID_FILE',
  kvMount: 'OPENBAO_KV_MOUNT',
  kvPrefix: 'OPENBAO_KV_PREFIX',
  approleMount: 'OPENBAO_APPROLE_MOUNT',
  timeoutMs: 'OPENBAO_TIMEOUT_MS',
  sshMount: 'OPENBAO_SSH_MOUNT',
  sshRole: 'OPENBAO_SSH_ROLE',
} as const;

/** Configuración tal como llega del entorno (todo opcional; se valida al cargar). */
export interface OpenBaoSource {
  addr?: string;
  roleId?: string;
  /** secret_id de AppRole en claro (OPENBAO_SECRET_ID). Mejor por fichero. */
  secretId?: string;
  /** Ruta a un fichero con el secret_id (OPENBAO_SECRET_ID_FILE), p. ej. un secret de Podman. */
  secretIdFile?: string;
  kvMount?: string;
  kvPrefix?: string;
  approleMount?: string;
  timeoutMs?: number;
  /** Montaje del motor SSH en modo CA (OPENBAO_SSH_MOUNT, `infraward-ssh`). */
  sshMount?: string;
  /** Rol de firma (OPENBAO_SSH_ROLE, `inventory`). */
  sshRole?: string;
}

/** Credenciales de AppRole. El secret_id no sale en `toString`, `JSON.stringify` ni `console.log`. */
export class AppRoleCredentials {
  readonly #secretId: string;

  constructor(
    readonly roleId: string,
    secretId: string,
  ) {
    this.#secretId = secretId;
  }

  secretId(): string {
    return this.#secretId;
  }

  toString(): string {
    return `AppRoleCredentials(${this.roleId})`;
  }

  toJSON(): { roleId: string } {
    return { roleId: this.roleId };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}

export interface OpenBaoConfig {
  /** URL base sin barra final, p. ej. https://bao.example:8200. */
  addr: string;
  credentials: AppRoleCredentials;
  kvMount: string;
  /** Prefijo dentro del KV bajo el que viven las rutas de las referencias ('' = ninguno). */
  kvPrefix: string;
  approleMount: string;
  timeoutMs: number;
  sshMount: string;
  sshRole: string;
  /** true si el token viajaría en claro a un host que no es loopback. */
  insecureTransport: boolean;
}

const SEGMENTS = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;

/** Segmentos `[A-Za-z0-9._-]` separados por `/`, sin `.` ni `..`. */
function validPath(path: string): boolean {
  return (
    SEGMENTS.test(path) && path.split('/').every((s) => s !== '.' && s !== '..')
  );
}
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/**
 * Valida la configuración del proveedor OpenBao. Los errores nombran la variable y qué
 * falla, nunca su valor.
 */
export function loadOpenBaoConfig(
  source: OpenBaoSource,
  names: Record<keyof typeof OPENBAO_ENV, string> = OPENBAO_ENV,
): OpenBaoConfig {
  const set = (v: string | undefined): v is string =>
    v !== undefined && v.trim() !== '';

  if (!set(source.addr)) {
    throw new Error(`OpenBao: falta ${names.addr}`);
  }
  let url: URL;
  try {
    url = new URL(source.addr.trim());
  } catch {
    throw new Error(`${names.addr}: no es una URL válida`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`${names.addr}: debe ser http:// o https://`);
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(
      `${names.addr}: sin usuario, contraseña, query ni fragmento`,
    );
  }

  if (!set(source.roleId)) {
    throw new Error(`OpenBao: falta ${names.roleId}`);
  }
  const hasSecret = set(source.secretId);
  const hasFile = set(source.secretIdFile);
  if (hasSecret === hasFile) {
    throw new Error(
      hasSecret
        ? `OpenBao: define solo una de ${names.secretId} o ${names.secretIdFile}`
        : `OpenBao: falta ${names.secretIdFile} o ${names.secretId}`,
    );
  }
  let secretId: string;
  if (hasFile) {
    try {
      secretId = readFileSync(source.secretIdFile!, 'utf8').trim();
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code ?? 'error';
      throw new Error(
        `${names.secretIdFile}: no se puede leer el fichero (${code})`,
        { cause: e },
      );
    }
    if (secretId === '') {
      throw new Error(`${names.secretIdFile}: el fichero está vacío`);
    }
  } else {
    secretId = source.secretId!.trim();
  }

  const kvMount = mountPath(source.kvMount, 'secret', names.kvMount);
  const approleMount = mountPath(
    source.approleMount,
    'approle',
    names.approleMount,
  );
  const sshMount = mountPath(
    source.sshMount,
    'infraward-ssh',
    names.sshMount,
  );
  const sshRole = (source.sshRole ?? 'inventory').trim();
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(sshRole)) {
    throw new Error(`${names.sshRole}: nombre de rol inválido`);
  }
  const kvPrefix = (source.kvPrefix ?? 'infraward')
    .trim()
    .replace(/^\/+|\/+$/g, '');
  if (kvPrefix !== '' && !validPath(kvPrefix)) {
    throw new Error(`${names.kvPrefix}: ruta inválida`);
  }

  const timeoutMs = source.timeoutMs ?? 5000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60000) {
    throw new Error(`${names.timeoutMs}: entre 100 y 60000 ms`);
  }

  return {
    addr: url.toString().replace(/\/+$/, ''),
    credentials: new AppRoleCredentials(source.roleId.trim(), secretId),
    kvMount,
    kvPrefix,
    approleMount,
    timeoutMs,
    sshMount,
    sshRole,
    insecureTransport: url.protocol === 'http:' && !LOOPBACK.has(url.hostname),
  };
}

function mountPath(
  value: string | undefined,
  fallback: string,
  env: string,
): string {
  const path = (value ?? fallback).trim().replace(/^\/+|\/+$/g, '');
  if (!validPath(path)) throw new Error(`${env}: ruta inválida`);
  return path;
}

/** Construye el origen de configuración a partir de las variables OPENBAO_* (o del ConfigService). */
export function openBaoSourceFromEnv(
  get: (name: string) => string | number | undefined,
): OpenBaoSource {
  const str = (name: string) => {
    const v = get(name);
    return v === undefined ? undefined : String(v);
  };
  const timeout = get(OPENBAO_ENV.timeoutMs);
  return {
    addr: str(OPENBAO_ENV.addr),
    roleId: str(OPENBAO_ENV.roleId),
    secretId: str(OPENBAO_ENV.secretId),
    secretIdFile: str(OPENBAO_ENV.secretIdFile),
    kvMount: str(OPENBAO_ENV.kvMount),
    kvPrefix: str(OPENBAO_ENV.kvPrefix),
    approleMount: str(OPENBAO_ENV.approleMount),
    sshMount: str(OPENBAO_ENV.sshMount),
    sshRole: str(OPENBAO_ENV.sshRole),
    timeoutMs: timeout === undefined ? undefined : Number(timeout),
  };
}
