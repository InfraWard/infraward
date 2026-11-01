import { CVE_ID_PATTERN } from '@infraward/shared-types';
import { gunzipSync } from 'node:zlib';

export type FetchFn = typeof fetch;

/** Error de una fuente, con un mensaje apto para guardarse y mostrarse (sin cuerpo ni URL). */
export class IntelFeedError extends Error {}

/** Tamaño máximo descargado (el CSV de EPSS con gzip ronda 2 MB; el JSON de KEV, 1,5 MB). */
export const INTEL_MAX_DOWNLOAD = 64 * 1024 ** 2;
/** Tamaño máximo del CSV de EPSS ya descomprimido (~10 MB hoy). */
export const EPSS_MAX_CSV = 256 * 1024 ** 2;

export type ConditionalResult =
  | { status: 'not_modified' }
  | {
      status: 'ok';
      body: Buffer;
      etag: string | null;
      lastModified: string | null;
    };

/**
 * GET condicional (`If-None-Match` / `If-Modified-Since`) con tope de tamaño y de tiempo. Un 304
 * no descarga nada. Los errores solo llevan el estado HTTP o el tipo de fallo.
 */
export async function fetchConditional(
  url: string,
  cache: { etag: string | null; lastModified: string | null },
  timeoutMs: number,
  fetchFn: FetchFn = fetch,
  maxBytes = INTEL_MAX_DOWNLOAD,
): Promise<ConditionalResult> {
  const headers: Record<string, string> = { 'user-agent': 'InfraWard' };
  if (cache.etag) headers['if-none-match'] = cache.etag;
  if (cache.lastModified) headers['if-modified-since'] = cache.lastModified;
  let res: Response;
  try {
    res = await fetchFn(url, {
      method: 'GET',
      headers,
      redirect: 'follow',
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    const name = (error as Error).name;
    throw new IntelFeedError(
      name === 'TimeoutError' || name === 'AbortError'
        ? `sin respuesta en ${Math.round(timeoutMs / 1000)} s`
        : 'no se pudo conectar',
    );
  }
  if (res.status === 304) {
    await res.body?.cancel();
    return { status: 'not_modified' };
  }
  if (!res.ok) {
    await res.body?.cancel();
    throw new IntelFeedError(`HTTP ${res.status}`);
  }
  const length = Number(res.headers.get('content-length'));
  if (length > maxBytes) {
    await res.body?.cancel();
    throw new IntelFeedError('respuesta demasiado grande');
  }
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for await (const chunk of res.body ?? []) {
      total += chunk.length;
      if (total > maxBytes)
        throw new IntelFeedError('respuesta demasiado grande');
      chunks.push(Buffer.from(chunk));
    }
  } catch (error) {
    if (error instanceof IntelFeedError) throw error;
    throw new IntelFeedError('descarga interrumpida');
  }
  return {
    status: 'ok',
    body: Buffer.concat(chunks),
    etag: header(res, 'etag', 512),
    lastModified: header(res, 'last-modified', 64),
  };
}

function header(res: Response, name: string, max: number): string | null {
  const v = res.headers.get(name);
  return v && v.length <= max ? v : null;
}

export interface KevCatalog {
  version: string;
  entries: {
    vulnerabilityId: string;
    added: string | null;
    due: string | null;
    ransomware: boolean;
    name: string | null;
  }[];
}

const DATE = /^\d{4}-\d{2}-\d{2}$/;

/** Catálogo KEV de CISA (`known_exploited_vulnerabilities.json`). */
export function parseKev(body: Buffer): KevCatalog {
  let json: unknown;
  try {
    json = JSON.parse(body.toString('utf8'));
  } catch {
    throw new IntelFeedError('el catálogo KEV no es JSON');
  }
  const r = json as { catalogVersion?: unknown; vulnerabilities?: unknown };
  if (!r || typeof r !== 'object' || !Array.isArray(r.vulnerabilities))
    throw new IntelFeedError('catálogo KEV no reconocido');
  const seen = new Set<string>();
  const entries: KevCatalog['entries'] = [];
  for (const v of r.vulnerabilities as Record<string, unknown>[]) {
    const id = typeof v?.cveID === 'string' ? v.cveID.trim().toUpperCase() : '';
    if (!CVE_ID_PATTERN.test(id) || seen.has(id)) continue;
    seen.add(id);
    const date = (x: unknown) =>
      typeof x === 'string' && DATE.test(x) ? x : null;
    const name =
      typeof v.vulnerabilityName === 'string'
        ? v.vulnerabilityName.slice(0, 500)
        : null;
    entries.push({
      vulnerabilityId: id,
      added: date(v.dateAdded),
      due: date(v.dueDate),
      ransomware:
        String(v.knownRansomwareCampaignUse ?? '').toLowerCase() === 'known',
      name,
    });
  }
  if (entries.length === 0) throw new IntelFeedError('catálogo KEV vacío');
  const version =
    typeof r.catalogVersion === 'string' && r.catalogVersion.length <= 64
      ? r.catalogVersion
      : `${entries.length}`;
  return { version, entries };
}

export interface EpssScores {
  /** `score_date` de la cabecera (o la fecha de hoy si no viene). */
  version: string;
  rows: { vulnerabilityId: string; epss: number; percentile: number | null }[];
}

/**
 * CSV de EPSS (con o sin gzip): `#model_version:…,score_date:2026-10-18T00:00:00+0000`, la
 * cabecera `cve,epss,percentile` y una fila por CVE.
 */
export function parseEpss(body: Buffer): EpssScores {
  let text: string;
  try {
    const gz = body[0] === 0x1f && body[1] === 0x8b;
    text = (
      gz ? gunzipSync(body, { maxOutputLength: EPSS_MAX_CSV }) : body
    ).toString('utf8');
  } catch {
    throw new IntelFeedError('el fichero de EPSS no se pudo descomprimir');
  }
  let version: string | null = null;
  let columns: string[] | null = null;
  const rows: EpssScores['rows'] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('#')) {
      const date = /score_date:(\d{4}-\d{2}-\d{2})/.exec(line)?.[1];
      if (date) version = date;
      continue;
    }
    const cells = line.split(',');
    if (!columns) {
      columns = cells.map((c) => c.trim().toLowerCase());
      continue;
    }
    const cve = cells[columns.indexOf('cve')]?.trim().toUpperCase() ?? '';
    const epss = Number(cells[columns.indexOf('epss')]);
    const pctCell = cells[columns.indexOf('percentile')]?.trim();
    const pct = pctCell ? Number(pctCell) : Number.NaN;
    if (!CVE_ID_PATTERN.test(cve) || !(epss >= 0 && epss <= 1)) continue;
    rows.push({
      vulnerabilityId: cve,
      epss,
      percentile: pct >= 0 && pct <= 1 ? pct : null,
    });
  }
  if (
    !columns?.includes('cve') ||
    !columns.includes('epss') ||
    rows.length === 0
  )
    throw new IntelFeedError('fichero de EPSS no reconocido');
  return { version: version ?? new Date().toISOString().slice(0, 10), rows };
}
