import { DomainApiError, type DomainApi } from '@infraward/connectors';

export type FetchFn = typeof fetch;

/** Tamaño máximo de una respuesta JSON (las páginas de registros son las más grandes). */
const MAX_BODY_BYTES = 32 * 1024 ** 2;

/**
 * GET de un JSON con timeout. Los errores llevan solo el estado HTTP y, si el cuerpo es un JSON
 * con `errors[0].code` (Cloudflare), ese código: nunca el cuerpo ni las cabeceras.
 */
export async function getJson(
  url: string,
  headers: Record<string, string>,
  timeoutMs: number,
  fetchFn: FetchFn = fetch,
): Promise<unknown> {
  let res: Response;
  try {
    res = await fetchFn(url, {
      method: 'GET',
      headers: { accept: 'application/json', ...headers },
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    const name = (error as Error).name;
    throw new DomainApiError(
      name === 'TimeoutError' || name === 'AbortError'
        ? `sin respuesta en ${timeoutMs} ms`
        : 'no se pudo conectar',
      null,
    );
  }
  let body: unknown = null;
  try {
    const text = await res.text();
    if (text.length > MAX_BODY_BYTES)
      throw new DomainApiError('respuesta demasiado grande', res.status);
    body = text ? JSON.parse(text) : null;
  } catch (error) {
    if (error instanceof DomainApiError) throw error;
    if (res.ok) throw new DomainApiError('respuesta que no es JSON', res.status);
  }
  if (!res.ok) {
    const code = providerCode(body);
    throw new DomainApiError(
      `HTTP ${res.status}${code === null ? '' : ` (código ${code})`}`,
      res.status,
      code,
    );
  }
  return body;
}

function providerCode(body: unknown): number | null {
  const errors = (body as { errors?: unknown } | null)?.errors;
  const code = Array.isArray(errors)
    ? (errors[0] as { code?: unknown } | undefined)?.code
    : undefined;
  return typeof code === 'number' && Number.isInteger(code) ? code : null;
}

/**
 * API de un proveedor ya autenticada con su token (Bearer). El token vive en un campo privado
 * de este objeto mientras dura el job y nunca sale en errores ni logs.
 */
export class BearerApi implements DomainApi {
  readonly #token: string;

  constructor(
    private readonly baseUrl: string,
    token: string,
    private readonly timeoutMs: number,
    private readonly fetchFn: FetchFn = fetch,
  ) {
    this.#token = token;
  }

  getJson(path: string, query: Record<string, string | number> = {}): Promise<unknown> {
    const url = new URL(`${this.baseUrl.replace(/\/$/, '')}${path}`);
    for (const [k, v] of Object.entries(query)) url.searchParams.set(k, String(v));
    return getJson(
      url.toString(),
      { authorization: `Bearer ${this.#token}` },
      this.timeoutMs,
      this.fetchFn,
    );
  }

  /** Que nunca se serialice el token por accidente (logs de objetos). */
  toJSON(): Record<string, string> {
    return { baseUrl: this.baseUrl };
  }
}
