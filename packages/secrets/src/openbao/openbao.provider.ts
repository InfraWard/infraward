import { Logger } from '@nestjs/common';
import {
  SecretFieldNotFoundError,
  SecretNotFoundError,
  SecretProviderError,
} from '../errors.js';
import {
  SSH_CERTIFICATE_EXTENSIONS,
  type SecretProvider,
  type SshCaPublicKey,
  type SshCertificateCapable,
  type SshCertificateRequest,
} from '../secret-provider.js';
import { parseSshPublicKey, sshPublicKeyFingerprint } from '../ssh-keys.js';
import {
  OpenBaoHttp,
  OpenBaoTokenManager,
  type FetchFn,
  type OpenBaoResponse,
} from './openbao-client.js';
import type { OpenBaoConfig } from './openbao-config.js';

const PRINCIPAL = /^[a-z_][a-z0-9_-]{0,31}$/;
// Admite el email de la persona en el key_id de la terminal (`user=ana@example.com`).
const KEY_ID = /^[A-Za-z0-9:=._@+-]{1,200}$/;
const MIN_CERT_TTL = 30;
const MAX_CERT_TTL = 3600;

/**
 * Proveedor `openbao`: secretos en un motor KV v2, con la app autenticada por AppRole.
 * La ruta de la referencia se cuelga de `kvPrefix` (por defecto `infraward/`), de modo que
 * la política de la app puede limitarse a ese subárbol. Los valores nunca se loguean.
 *
 * CA SSH (`SshCertificateCapable`): el motor SSH en modo CA (`sshMount`) firma claves efímeras
 * con el rol `sshRole`. La clave privada de la CA se generó dentro de OpenBao y no sale de él.
 */
export class OpenBaoSecretProvider
  implements SecretProvider, SshCertificateCapable
{
  readonly id = 'openbao';
  private readonly http: OpenBaoHttp;
  private readonly tokens: OpenBaoTokenManager;

  constructor(
    private readonly config: OpenBaoConfig,
    fetchFn?: FetchFn,
  ) {
    this.http = new OpenBaoHttp(config, fetchFn);
    this.tokens = new OpenBaoTokenManager(config, this.http);
    if (config.insecureTransport) {
      new Logger('OpenBaoSecretProvider').warn(
        'OPENBAO_ADDR usa http:// hacia un host que no es local: el token y los secretos viajan sin cifrar',
      );
    }
  }

  /** Accessor del token actual de la app (no es secreto). */
  get tokenAccessor(): string | undefined {
    return this.tokens.currentAccessor;
  }

  async get(path: string, field?: string): Promise<string> {
    const res = await this.call('GET', this.kv('data', path), path);
    if (res.status === 404) throw new SecretNotFoundError(this.id, path);
    this.expect(res, 200, path);
    const data = (res.body?.data as Record<string, unknown> | undefined)
      ?.data as Record<string, unknown> | null | undefined;
    // KV v2 devuelve data: null si la última versión está borrada o destruida.
    if (!data || typeof data !== 'object') {
      throw new SecretNotFoundError(this.id, path);
    }
    const fields = Object.keys(data);
    let name: string;
    if (field === undefined) {
      if (fields.length !== 1) {
        throw new SecretFieldNotFoundError(this.id, path, undefined);
      }
      name = fields[0];
    } else {
      if (!Object.hasOwn(data, field)) {
        throw new SecretFieldNotFoundError(this.id, path, field);
      }
      name = field;
    }
    const value = data[name];
    if (typeof value !== 'string') {
      throw new SecretProviderError(
        this.id,
        path,
        `el campo ${name} no es texto`,
      );
    }
    return value;
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
    const res = await this.call('POST', this.kv('data', path), path, { data });
    this.expect(res, [200, 204], path);
  }

  /** Borra la ruta con todas sus versiones (metadata). */
  async delete(path: string): Promise<boolean> {
    const meta = await this.call('GET', this.kv('metadata', path), path);
    if (meta.status === 404) return false;
    this.expect(meta, 200, path);
    const res = await this.call('DELETE', this.kv('metadata', path), path);
    this.expect(res, [200, 204], path);
    return true;
  }

  async signSshKey(request: SshCertificateRequest): Promise<string> {
    const where = `${this.config.sshMount}/sign/${this.config.sshRole}`;
    const key = parseSshPublicKey(request.publicKey);
    if (key?.type !== 'ssh-ed25519')
      throw new TypeError('Solo se firman claves públicas ssh-ed25519');
    if (!PRINCIPAL.test(request.principal))
      throw new TypeError('Principal SSH inválido');
    if (!KEY_ID.test(request.keyId)) throw new TypeError('key_id inválido');
    const extensions = request.extensions ?? [];
    if (extensions.some((e) => !SSH_CERTIFICATE_EXTENSIONS.includes(e)))
      throw new TypeError('Extensión de certificado no permitida');
    if (
      !Number.isInteger(request.ttlSeconds) ||
      request.ttlSeconds < MIN_CERT_TTL ||
      request.ttlSeconds > MAX_CERT_TTL
    )
      throw new TypeError(
        `TTL del certificado entre ${MIN_CERT_TTL} y ${MAX_CERT_TTL} s`,
      );
    const res = await this.call('POST', where, where, {
      public_key: `${key.type} ${key.blob}`,
      valid_principals: request.principal,
      key_id: request.keyId,
      ttl: `${request.ttlSeconds}s`,
      cert_type: 'user',
      ...(extensions.length > 0 && {
        extensions: Object.fromEntries(extensions.map((e) => [e, ''])),
      }),
    });
    if (res.status === 400)
      throw new SecretProviderError(
        this.id,
        where,
        'OpenBao rechazó la firma (HTTP 400): revisa el rol (principal, key_id o TTL permitidos)',
      );
    this.expect(res, 200, where);
    const signed = (res.body?.data as Record<string, unknown> | undefined)
      ?.signed_key;
    const cert = typeof signed === 'string' ? signed.trim() : '';
    if (parseSshPublicKey(cert)?.type !== 'ssh-ed25519-cert-v01@openssh.com')
      throw new SecretProviderError(
        this.id,
        where,
        'la respuesta no contiene un certificado SSH',
      );
    return cert;
  }

  async sshCaPublicKeys(): Promise<SshCaPublicKey[]> {
    const where = `${this.config.sshMount}/issuers`;
    const res = await this.call('GET', `${where}?list=true`, where);
    // Sin emisores, OpenBao responde 404 a un LIST.
    if (res.status === 404) return [];
    this.expect(res, 200, where);
    const info = (res.body?.data as Record<string, unknown> | undefined)
      ?.key_info as Record<string, Record<string, unknown>> | undefined;
    const keys: SshCaPublicKey[] = [];
    for (const issuer of Object.values(info ?? {})) {
      const line =
        typeof issuer.public_key === 'string' ? issuer.public_key.trim() : '';
      const key = parseSshPublicKey(line);
      if (!key) continue;
      const publicKey = `${key.type} ${key.blob}`;
      keys.push({
        publicKey,
        fingerprint: sshPublicKeyFingerprint(publicKey),
        active: issuer.is_default === true,
      });
    }
    // La activa primero; el resto, en orden estable.
    return keys.sort(
      (a, b) =>
        Number(b.active) - Number(a.active) ||
        a.fingerprint.localeCompare(b.fingerprint),
    );
  }

  async healthCheck(): Promise<boolean> {
    try {
      const res = await this.call('GET', 'auth/token/lookup-self', undefined);
      return res.status === 200;
    } catch {
      return false;
    }
  }

  close(): Promise<void> {
    return this.tokens.close();
  }

  toJSON(): object {
    return { id: this.id, addr: this.config.addr };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `OpenBaoSecretProvider(${this.config.addr})`;
  }

  /** Petición autenticada; con 403 descarta el token (p. ej. revocado) y reintenta una vez. */
  private async call(
    method: string,
    apiPath: string,
    path: string | undefined,
    body?: unknown,
  ): Promise<OpenBaoResponse> {
    for (let attempt = 0; ; attempt++) {
      const token = await this.tokens.token();
      const res = await this.http.request(method, apiPath, {
        token,
        body,
        context: path,
      });
      if (res.status !== 403 || attempt > 0) return res;
      this.tokens.invalidate(token);
    }
  }

  private expect(
    res: OpenBaoResponse,
    ok: number | number[],
    path: string,
  ): void {
    const accepted = Array.isArray(ok) ? ok : [ok];
    if (accepted.includes(res.status)) return;
    throw new SecretProviderError(
      this.id,
      path,
      res.status === 403
        ? 'permiso denegado (revisa la política de la app)'
        : res.status === 503
          ? 'OpenBao sellado o no disponible (HTTP 503)'
          : `respuesta inesperada (HTTP ${res.status})`,
    );
  }

  private kv(kind: 'data' | 'metadata', path: string): string {
    const full = this.config.kvPrefix
      ? `${this.config.kvPrefix}/${path}`
      : path;
    const encoded = full.split('/').map(encodeURIComponent).join('/');
    return `${this.config.kvMount}/${kind}/${encoded}`;
  }
}
