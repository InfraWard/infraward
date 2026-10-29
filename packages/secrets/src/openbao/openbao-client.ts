import { Logger } from '@nestjs/common';
import { SecretProviderError } from '../errors.js';
import type { OpenBaoConfig } from './openbao-config.js';

const PROVIDER = 'openbao';

/** Mínimo de `fetch` que necesita el cliente (inyectable en los tests). */
export type FetchFn = (
  input: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body?: string;
    signal: AbortSignal;
    /** Siempre `error`: nunca se sigue una redirección (ver `OpenBaoHttp.request`). */
    redirect: 'error';
  },
) => Promise<{ status: number; json(): Promise<unknown> }>;

export interface OpenBaoResponse {
  status: number;
  /** Cuerpo JSON, o null si no hay (204) o no es JSON. Nunca se loguea. */
  body: Record<string, unknown> | null;
}

/** Datos del token de la app que interesan (el propio token va aparte, en un campo privado). */
interface AuthInfo {
  token: string;
  accessor: string;
  leaseSeconds: number;
  renewable: boolean;
}

/**
 * Peticiones HTTP a OpenBao. Los fallos de red y los tiempos de espera se convierten en
 * `SecretProviderError` con el tipo de fallo; los cuerpos de respuesta nunca van al mensaje.
 */
export class OpenBaoHttp {
  constructor(
    private readonly config: OpenBaoConfig,
    private readonly fetchFn: FetchFn = fetch as unknown as FetchFn,
  ) {}

  async request(
    method: string,
    path: string,
    options: { token?: string; body?: unknown; context?: string } = {},
  ): Promise<OpenBaoResponse> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (options.token !== undefined) headers['X-Vault-Token'] = options.token;
    if (options.body !== undefined)
      headers['Content-Type'] = 'application/json';
    let res: Awaited<ReturnType<FetchFn>>;
    try {
      res = await this.fetchFn(`${this.config.addr}/v1/${path}`, {
        method,
        headers,
        body:
          options.body === undefined ? undefined : JSON.stringify(options.body),
        signal: AbortSignal.timeout(this.config.timeoutMs),
        // OpenBao no redirige en su API. Seguir un 307/308 reenviaría el login de AppRole
        // (role_id y secret_id) o el X-Vault-Token a otro sitio (revisión #3, M8).
        redirect: 'error',
      });
    } catch (e) {
      const name = (e as Error)?.name;
      throw new SecretProviderError(
        PROVIDER,
        options.context,
        name === 'TimeoutError' || name === 'AbortError'
          ? `sin respuesta en ${this.config.timeoutMs} ms`
          : isRedirect(e)
            ? 'respondió con una redirección (no se sigue)'
            : 'no se pudo conectar',
      );
    }
    let body: Record<string, unknown> | null = null;
    if (res.status !== 204) {
      try {
        const parsed = await res.json();
        if (parsed && typeof parsed === 'object') {
          body = parsed as Record<string, unknown>;
        }
      } catch {
        body = null;
      }
    }
    return { status: res.status, body };
  }
}

/** El `fetch` de Node (undici) con `redirect: 'error'` falla con «unexpected redirect». */
function isRedirect(e: unknown): boolean {
  const cause = (e as { cause?: { message?: unknown } } | null)?.cause;
  return typeof cause?.message === 'string' && /redirect/i.test(cause.message);
}

/**
 * Token de la app en OpenBao, obtenido con AppRole (nunca un token root):
 * - login perezoso y de un solo vuelo (peticiones concurrentes esperan al mismo login);
 * - renovación programada al ~2/3 de su vida; si ya no se puede alargar (se acerca a
 *   `token_max_ttl`), no es renovable o la renovación falla, vuelve a hacer login;
 * - `invalidate` lo descarta (p. ej. tras un 403 porque lo revocaron desde fuera).
 * El token vive en un campo privado: no sale al inspeccionar ni serializar el objeto.
 */
export class OpenBaoTokenManager {
  #token: string | undefined;
  private accessor: string | undefined;
  private initialLeaseSeconds = 0;
  private loginInFlight: Promise<string> | undefined;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private closed = false;
  private readonly logger = new Logger('OpenBaoSecretProvider');

  constructor(
    private readonly config: OpenBaoConfig,
    private readonly http: OpenBaoHttp,
  ) {}

  /** Accessor del token actual (no es secreto; sirve para auditar en OpenBao). */
  get currentAccessor(): string | undefined {
    return this.accessor;
  }

  async token(): Promise<string> {
    if (this.closed) {
      throw new SecretProviderError(PROVIDER, undefined, 'proveedor cerrado');
    }
    if (this.#token !== undefined) return this.#token;
    return this.login();
  }

  /** Descarta el token si sigue siendo el actual; el siguiente uso hará login. */
  invalidate(token: string): void {
    if (this.#token === token) this.drop();
  }

  /** Cancela la renovación y revoca el token (sin esperar a OpenBao si no responde). */
  async close(): Promise<void> {
    this.closed = true;
    const token = this.#token;
    this.drop();
    if (token === undefined) return;
    try {
      await this.http.request('POST', 'auth/token/revoke-self', { token });
    } catch {
      // Caducará solo; al cerrar no merece la pena insistir.
    }
  }

  toJSON(): object {
    return { accessor: this.accessor };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `OpenBaoTokenManager(accessor=${this.accessor ?? '-'})`;
  }

  private login(): Promise<string> {
    this.loginInFlight ??= this.doLogin().finally(() => {
      this.loginInFlight = undefined;
    });
    return this.loginInFlight;
  }

  private async doLogin(): Promise<string> {
    const { credentials, approleMount } = this.config;
    const res = await this.http.request('POST', `auth/${approleMount}/login`, {
      body: { role_id: credentials.roleId, secret_id: credentials.secretId() },
      context: 'login AppRole',
    });
    if (res.status !== 200) {
      throw new SecretProviderError(
        PROVIDER,
        undefined,
        `login AppRole rechazado (HTTP ${res.status})`,
      );
    }
    const auth = parseAuth(res.body);
    if (!auth) {
      throw new SecretProviderError(
        PROVIDER,
        undefined,
        'respuesta de login AppRole inesperada',
      );
    }
    if (this.closed) {
      // Cerrado mientras se hacía login: no dejar el token vivo.
      void this.http
        .request('POST', 'auth/token/revoke-self', { token: auth.token })
        .catch(() => undefined);
      throw new SecretProviderError(PROVIDER, undefined, 'proveedor cerrado');
    }
    this.drop();
    this.#token = auth.token;
    this.accessor = auth.accessor;
    this.initialLeaseSeconds = auth.leaseSeconds;
    this.schedule(auth.leaseSeconds, auth.renewable);
    return auth.token;
  }

  private schedule(leaseSeconds: number, renewable: boolean): void {
    if (leaseSeconds <= 0) return; // token sin caducidad: nada que renovar
    const delayMs = Math.max(Math.floor((leaseSeconds * 1000 * 2) / 3), 500);
    this.timer = setTimeout(() => {
      this.timer = undefined;
      void this.refresh(renewable);
    }, delayMs);
    this.timer.unref?.();
  }

  private async refresh(renewable: boolean): Promise<void> {
    const token = this.#token;
    if (token === undefined || this.closed) return;
    try {
      if (renewable) {
        const res = await this.http.request('POST', 'auth/token/renew-self', {
          token,
          context: 'renovación del token',
        });
        const auth = res.status === 200 ? parseAuth(res.body) : undefined;
        if (this.#token !== token) return; // otro login lo sustituyó entretanto
        // Si ya no se alarga lo suficiente es que se acerca a token_max_ttl: nuevo login.
        if (auth && auth.leaseSeconds * 2 >= this.initialLeaseSeconds) {
          this.schedule(auth.leaseSeconds, auth.renewable);
          return;
        }
      }
      if (this.#token !== token) return;
      this.drop();
      await this.login();
    } catch (e) {
      // Sin token: el siguiente uso volverá a intentar el login.
      if (this.#token === token) this.drop();
      this.logger.warn(
        `No se pudo renovar el token de OpenBao: ${(e as Error).message}`,
      );
    }
  }

  private drop(): void {
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
    this.#token = undefined;
    this.accessor = undefined;
  }
}

function parseAuth(body: Record<string, unknown> | null): AuthInfo | undefined {
  const auth = body?.auth as Record<string, unknown> | undefined;
  if (!auth || typeof auth.client_token !== 'string' || !auth.client_token) {
    return undefined;
  }
  return {
    token: auth.client_token,
    accessor: typeof auth.accessor === 'string' ? auth.accessor : '',
    leaseSeconds:
      typeof auth.lease_duration === 'number' ? auth.lease_duration : 0,
    renewable: auth.renewable === true,
  };
}
