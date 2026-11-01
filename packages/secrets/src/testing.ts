import { randomBytes } from 'node:crypto';
// Utilidades de test (no se exportan desde index.ts).
import type {
  EncryptedSecret,
  LocalSecretStore,
} from './local/local-secret.store.js';

/** Almacén en memoria con acceso directo a las filas para simular manipulaciones. */
export class MemoryLocalSecretStore implements LocalSecretStore {
  readonly rows = new Map<string, EncryptedSecret>();
  failPing = false;

  find(path: string): Promise<EncryptedSecret | null> {
    const row = this.rows.get(path);
    return Promise.resolve(row ? structuredClone(row) : null);
  }

  upsert(secret: EncryptedSecret): Promise<void> {
    this.rows.set(secret.path, structuredClone(secret));
    return Promise.resolve();
  }

  delete(path: string): Promise<boolean> {
    return Promise.resolve(this.rows.delete(path));
  }

  ping(): Promise<void> {
    return this.failPing
      ? Promise.reject(new Error('sin conexión'))
      : Promise.resolve();
  }
}

/** Token emitido por FakeOpenBao. */
interface FakeToken {
  accessor: string;
  expiresAt: number;
  maxExpiresAt: number;
  renewable: boolean;
}

/**
 * OpenBao falso en memoria (login AppRole, renew/lookup/revoke-self y KV v2 en `secret/`),
 * con contadores y palancas para simular caducidades, revocaciones y caídas.
 */
export class FakeOpenBao {
  readonly roleId = 'role-fake';
  readonly secretId = `secret-id-${Math.random().toString(36).slice(2)}`;
  tokenTtl = 60;
  tokenMaxTtl = 600;
  renewable = true;
  /** Si es true, todas las peticiones fallan como si no hubiera red. */
  down = false;
  /** Respuesta forzada (p. ej. 503 sellado) para las rutas KV. */
  kvStatus: number | undefined;
  readonly kv = new Map<string, { data: Record<string, unknown> | null }>();
  readonly tokens = new Map<string, FakeToken>();
  readonly calls: string[] = [];
  logins = 0;
  renewals = 0;
  /** Emisores de la CA SSH (montaje `infraward-ssh`). */
  sshIssuers: { publicKey: string; isDefault: boolean }[] = [];
  /** Peticiones de firma recibidas (cuerpo tal cual). */
  readonly sshSignRequests: Record<string, unknown>[] = [];
  /** Respuesta forzada para la firma (p. ej. 400 si el rol no lo permite). */
  sshSignStatus: number | undefined;
  private seq = 0;

  readonly fetch = async (
    input: string,
    init: { method: string; headers: Record<string, string>; body?: string },
  ): Promise<{ status: number; json(): Promise<unknown> }> => {
    const path = new URL(input).pathname.replace(/^\/v1\//, '');
    this.calls.push(`${init.method} ${path}`);
    if (this.down) throw new TypeError('fetch failed');
    const reply = (status: number, body?: unknown) => ({
      status,
      json: async () => {
        if (body === undefined) throw new SyntaxError('sin cuerpo');
        return body;
      },
    });
    const body = init.body
      ? (JSON.parse(init.body) as Record<string, unknown>)
      : {};

    if (path === 'auth/approle/login' && init.method === 'POST') {
      if (body.role_id !== this.roleId || body.secret_id !== this.secretId) {
        return reply(400, { errors: ['invalid role or secret ID'] });
      }
      this.logins++;
      const token = `s.fake-${++this.seq}-${Math.random().toString(36).slice(2)}`;
      const now = Date.now();
      const t: FakeToken = {
        accessor: `acc-${this.seq}`,
        expiresAt: now + this.tokenTtl * 1000,
        maxExpiresAt: now + this.tokenMaxTtl * 1000,
        renewable: this.renewable,
      };
      this.tokens.set(token, t);
      return reply(200, { auth: this.auth(token, t) });
    }

    const token = init.headers['X-Vault-Token'];
    const t = token ? this.tokens.get(token) : undefined;
    if (!t || t.expiresAt <= Date.now()) {
      return reply(403, { errors: ['permission denied'] });
    }
    switch (`${init.method} ${path}`) {
      case 'POST auth/token/renew-self': {
        if (!t.renewable) return reply(400, { errors: ['not renewable'] });
        this.renewals++;
        t.expiresAt = Math.min(
          Date.now() + this.tokenTtl * 1000,
          t.maxExpiresAt,
        );
        return reply(200, { auth: this.auth(token!, t) });
      }
      case 'GET auth/token/lookup-self':
        return reply(200, { data: { accessor: t.accessor } });
      case 'POST auth/token/revoke-self':
        this.tokens.delete(token!);
        return reply(204);
    }

    // El rol del inventario y el de la terminal (sesión 21).
    if (
      init.method === 'POST' &&
      (path === 'infraward-ssh/sign/inventory' || path === 'infraward-ssh/sign/infraward-operator')
    ) {
      this.sshSignRequests.push(body);
      if (this.sshSignStatus !== undefined)
        return reply(this.sshSignStatus, { errors: ['rechazado'] });
      return reply(200, { data: { signed_key: `${fakeSshCertificate()}\n` } });
    }
    if (init.method === 'GET' && path === 'infraward-ssh/issuers') {
      if (this.sshIssuers.length === 0) return reply(404, { errors: [] });
      const keyInfo = Object.fromEntries(
        this.sshIssuers.map((i, n) => [
          `issuer-${n}`,
          {
            issuer_name: `ca-${n}`,
            is_default: i.isDefault,
            public_key: `${i.publicKey}\n`,
          },
        ]),
      );
      return reply(200, {
        data: { keys: Object.keys(keyInfo), key_info: keyInfo },
      });
    }

    const kv = /^secret\/(data|metadata)\/(.+)$/.exec(path);
    if (!kv) return reply(404, { errors: [] });
    if (this.kvStatus !== undefined)
      return reply(this.kvStatus, { errors: [] });
    const [, kind, key] = kv;
    const entry = this.kv.get(decodeURIComponent(key));
    if (kind === 'data' && init.method === 'GET') {
      return entry
        ? reply(200, { data: { data: entry.data, metadata: { version: 1 } } })
        : reply(404, { errors: [] });
    }
    if (kind === 'data' && init.method === 'POST') {
      this.kv.set(decodeURIComponent(key), {
        data: body.data as Record<string, unknown>,
      });
      return reply(200, { data: { version: 1 } });
    }
    if (kind === 'metadata' && init.method === 'GET') {
      return entry
        ? reply(200, { data: { versions: {} } })
        : reply(404, { errors: [] });
    }
    if (kind === 'metadata' && init.method === 'DELETE') {
      this.kv.delete(decodeURIComponent(key));
      return reply(204);
    }
    return reply(405, { errors: [] });
  };

  /** Revoca todos los tokens, como si un operador lo hiciera desde fuera. */
  revokeAll(): void {
    this.tokens.clear();
  }

  private auth(token: string, t: FakeToken) {
    return {
      client_token: token,
      accessor: t.accessor,
      lease_duration: Math.max(
        0,
        Math.round((t.expiresAt - Date.now()) / 1000),
      ),
      renewable: t.renewable,
      policies: ['infraward'],
    };
  }
}

/** Línea con la forma de un certificado SSH ed25519 (no es un certificado válido). */
export function fakeSshCertificate(): string {
  const type = 'ssh-ed25519-cert-v01@openssh.com';
  const len = Buffer.alloc(4);
  len.writeUInt32BE(type.length);
  const blob = Buffer.concat([len, Buffer.from(type), randomBytes(64)]);
  return `${type} ${blob.toString('base64')}`;
}
