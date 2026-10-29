import { Logger } from '@nestjs/common';
import { SecretNotFoundError, SecretProviderError } from '../errors.js';
import {
  OpenBaoHttp,
  OpenBaoTokenManager,
  type FetchFn,
  type OpenBaoResponse,
} from '../openbao/openbao-client.js';
import type { OpenBaoConfig } from '../openbao/openbao-config.js';
import {
  VAULT_SECRET_FIELD,
  type VaultStore,
  type VaultStoredVersion,
} from './vault-store.js';

const PROVIDER = 'vault-openbao';

/**
 * Almacén de la caja fuerte en OpenBao: KV v2 bajo **su propio prefijo** (`infraward-vault/`) y
 * con **su propia AppRole** (política `infraward-vault`). La política de la app (`infraward`,
 * la que tiene también el worker) no alcanza ese prefijo: el worker no puede leerlo nunca.
 * Las versiones son las de KV v2; `max_versions` se fija en la metadata de cada ruta.
 */
export class OpenBaoVaultStore implements VaultStore {
  readonly provider = PROVIDER;
  private readonly http: OpenBaoHttp;
  private readonly tokens: OpenBaoTokenManager;

  constructor(
    private readonly config: OpenBaoConfig,
    readonly maxVersions: number,
    fetchFn?: FetchFn,
  ) {
    this.http = new OpenBaoHttp(config, fetchFn);
    this.tokens = new OpenBaoTokenManager(config, this.http);
    if (config.insecureTransport) {
      new Logger('OpenBaoVaultStore').warn(
        'OPENBAO_ADDR usa http:// hacia un host que no es local: las credenciales de la caja fuerte viajan sin cifrar',
      );
    }
  }

  async put(path: string, value: string): Promise<number> {
    if (typeof value !== 'string' || value === '') {
      throw new TypeError('El secreto es un texto no vacío');
    }
    const meta = await this.call('POST', this.kv('metadata', path), path, {
      max_versions: this.maxVersions,
    });
    this.expect(meta, [200, 204], path);
    const res = await this.call('POST', this.kv('data', path), path, {
      data: { [VAULT_SECRET_FIELD]: value },
    });
    this.expect(res, [200, 204], path);
    const version = (res.body?.data as Record<string, unknown> | undefined)?.version;
    if (typeof version !== 'number') {
      throw new SecretProviderError(PROVIDER, path, 'respuesta sin versión');
    }
    return version;
  }

  async get(
    path: string,
    version?: number,
  ): Promise<{ value: string; version: number }> {
    const query = version === undefined ? '' : `?version=${Math.trunc(version)}`;
    const res = await this.call('GET', `${this.kv('data', path)}${query}`, path);
    if (res.status === 404) throw new SecretNotFoundError(PROVIDER, path);
    this.expect(res, 200, path);
    const body = res.body?.data as Record<string, unknown> | undefined;
    const data = body?.data as Record<string, unknown> | null | undefined;
    const meta = body?.metadata as Record<string, unknown> | undefined;
    // data: null si esa versión está borrada o destruida.
    const value = data?.[VAULT_SECRET_FIELD];
    if (typeof value !== 'string') throw new SecretNotFoundError(PROVIDER, path);
    const got = typeof meta?.version === 'number' ? meta.version : version;
    if (typeof got !== 'number') {
      throw new SecretProviderError(PROVIDER, path, 'respuesta sin versión');
    }
    return { value, version: got };
  }

  async versions(path: string): Promise<VaultStoredVersion[]> {
    const res = await this.call('GET', this.kv('metadata', path), path);
    if (res.status === 404) return [];
    this.expect(res, 200, path);
    const versions = ((res.body?.data as Record<string, unknown> | undefined)
      ?.versions ?? {}) as Record<string, Record<string, unknown>>;
    return Object.entries(versions)
      .filter(([, v]) => v.destroyed !== true && !v.deletion_time)
      .map(([n, v]) => ({
        version: Number(n),
        createdAt:
          typeof v.created_time === 'string' ? new Date(v.created_time) : null,
      }))
      .filter((v) => Number.isInteger(v.version))
      .sort((a, b) => b.version - a.version);
  }

  async destroy(path: string): Promise<boolean> {
    const meta = await this.call('GET', this.kv('metadata', path), path);
    if (meta.status === 404) return false;
    this.expect(meta, 200, path);
    const res = await this.call('DELETE', this.kv('metadata', path), path);
    this.expect(res, [200, 204], path);
    return true;
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
    return { provider: this.provider, addr: this.config.addr };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `OpenBaoVaultStore(${this.config.addr})`;
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

  private expect(res: OpenBaoResponse, ok: number | number[], path: string): void {
    const accepted = Array.isArray(ok) ? ok : [ok];
    if (accepted.includes(res.status)) return;
    throw new SecretProviderError(
      PROVIDER,
      path,
      res.status === 403
        ? 'permiso denegado (revisa la política infraward-vault)'
        : res.status === 503
          ? 'OpenBao sellado o no disponible (HTTP 503)'
          : `respuesta inesperada (HTTP ${res.status})`,
    );
  }

  private kv(kind: 'data' | 'metadata', path: string): string {
    const full = this.config.kvPrefix ? `${this.config.kvPrefix}/${path}` : path;
    const encoded = full.split('/').map(encodeURIComponent).join('/');
    return `${this.config.kvMount}/${kind}/${encoded}`;
  }
}
