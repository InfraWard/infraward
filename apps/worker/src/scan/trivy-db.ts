import type {
  CvssScore,
  VulnerabilityDetails,
  VulnerabilityLookupJobResult,
} from '@infraward/shared-types';
import { open, readFile, realpath, type FileHandle } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * Consulta de un CVE en la BD de vulnerabilidades de Trivy (`<caché>/current/db/trivy.db`,
 * BoltDB), DESIGN §9. Lee la generación vigente (`current`, que solo apunta a generaciones
 * completas: nunca a una descarga a medias, DESIGN §20) o, si aún no hay ninguna, la caché de
 * antes de las generaciones. Lector de solo lectura propio, sin dependencias: abre el fichero con
 * `O_RDONLY`, lee páginas con lecturas posicionales y lo cierra. **Sin flock ni mmap**: nunca
 * bloquea a Trivy. Cualquier cosa que no cuadre (esquema de Trivy desconocido, meta inválida,
 * páginas fuera de rango) da `unavailable` con el motivo, nunca un resultado a medias.
 */

/** Versión del esquema de trivy-db que sabemos leer (`metadata.json` → `Version`). */
export const TRIVY_DB_SCHEMA_VERSION = 2;
/** Bucket raíz con los detalles de cada vulnerabilidad (JSON por id). */
const VULNERABILITY_BUCKET = 'vulnerability';
/** Enlace a la generación vigente (lo publica `TrivyRunner` al terminar cada descarga). */
const CURRENT = 'current';

const BOLT_MAGIC = 0xed0cdaed;
const BOLT_VERSION = 2;
const PAGE_HEADER = 16;
const ELEMENT_SIZE = 16;
const BUCKET_HEADER = 16;
const BRANCH = 0x01;
const LEAF = 0x02;
const META = 0x04;
const BUCKET_LEAF = 0x01;
/** Profundidad máxima del B+árbol (protección ante un fichero corrupto o en plena escritura). */
const MAX_DEPTH = 32;
/** Tope de páginas de overflow de un nodo (64 MiB con páginas de 4 KiB). */
const MAX_OVERFLOW = 16_384;

export class TrivyDbError extends Error {}

export class TrivyDb {
  constructor(private readonly cacheDir: string) {}

  async lookup(vulnerabilityId: string): Promise<VulnerabilityLookupJobResult> {
    let dbUpdatedAt: string | null = null;
    try {
      // Se resuelve una vez: aunque se publique otra generación a mitad, se lee entera esta.
      const generation = await realpath(join(this.cacheDir, CURRENT)).catch(
        () => this.cacheDir,
      );
      const metadata = await this.metadata(generation);
      dbUpdatedAt = metadata.updatedAt;
      const raw = await readBoltValue(
        join(generation, 'db', 'trivy.db'),
        [VULNERABILITY_BUCKET],
        vulnerabilityId,
      );
      if (raw === null)
        return { status: 'not_found', details: null, dbUpdatedAt, reason: null };
      return {
        status: 'found',
        details: parseVulnerability(raw),
        dbUpdatedAt,
        reason: null,
      };
    } catch (error) {
      if (!(error instanceof TrivyDbError)) throw error;
      return {
        status: 'unavailable',
        details: null,
        dbUpdatedAt,
        reason: error.message,
      };
    }
  }

  /** `db/metadata.json`: versión del esquema (tiene que ser la conocida) y fecha de la BD. */
  private async metadata(
    generation: string,
  ): Promise<{ updatedAt: string | null }> {
    let text: string;
    try {
      text = await readFile(join(generation, 'db', 'metadata.json'), 'utf8');
    } catch {
      throw new TrivyDbError('No hay BD de Trivy descargada en el worker');
    }
    let meta: Record<string, unknown>;
    try {
      meta = JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new TrivyDbError('metadata.json de la BD de Trivy ilegible');
    }
    if (meta.Version !== TRIVY_DB_SCHEMA_VERSION)
      throw new TrivyDbError(
        `Esquema de la BD de Trivy no reconocido (versión ${String(meta.Version)}, se esperaba ${TRIVY_DB_SCHEMA_VERSION})`,
      );
    return {
      updatedAt: typeof meta.UpdatedAt === 'string' ? meta.UpdatedAt : null,
    };
  }
}

/**
 * Valor de `key` dentro de los buckets anidados `buckets` de un fichero BoltDB (null si no está).
 * Solo lectura y sin candados.
 */
export async function readBoltValue(
  path: string,
  buckets: string[],
  key: string,
): Promise<Buffer | null> {
  let fh: FileHandle;
  try {
    fh = await open(path, 'r');
  } catch {
    throw new TrivyDbError('No se puede abrir la BD de Trivy');
  }
  try {
    const reader = new BoltReader(fh);
    const meta = await reader.meta();
    let node: Node = { kind: 'page', pgid: meta.root };
    for (const name of buckets) {
      const hit = await reader.get(node, Buffer.from(name));
      if (!hit?.bucket) return null;
      node = bucketRoot(hit.value);
    }
    const hit = await reader.get(node, Buffer.from(key));
    return hit && !hit.bucket ? hit.value : null;
  } finally {
    await fh.close();
  }
}

interface Meta {
  pageSize: number;
  root: bigint;
  highWater: bigint;
  txid: bigint;
}

/** Raíz de un bucket: una página o, si es pequeño, la página inline que va en su valor. */
type Node = { kind: 'page'; pgid: bigint } | { kind: 'inline'; page: Buffer };

class BoltReader {
  private m: Meta | null = null;

  constructor(private readonly fh: FileHandle) {}

  /** Meta válida con el txid mayor de las dos (páginas 0 y 1), como hace bbolt. */
  async meta(): Promise<Meta> {
    const first = await this.read(0n, 4096);
    const m0 = parseMeta(first);
    const pageSize = m0?.pageSize ?? 4096;
    const m1 = parseMeta(await this.read(BigInt(pageSize), pageSize));
    const valid = [m0, m1].filter(
      (m): m is Meta => !!m && m.pageSize === pageSize,
    );
    if (!valid.length)
      throw new TrivyDbError('BD de Trivy no válida (cabecera de BoltDB)');
    this.m = valid.reduce((a, b) => (b.txid > a.txid ? b : a), valid[0]);
    return this.m;
  }

  /** Busca `key` desde `node`; `bucket` indica si el valor es un bucket anidado. */
  async get(
    node: Node,
    key: Buffer,
  ): Promise<{ value: Buffer; bucket: boolean } | null> {
    let page = await this.page(node);
    for (let depth = 0; depth < MAX_DEPTH; depth++) {
      const flags = page.readUInt16LE(8);
      const count = page.readUInt16LE(10);
      if (flags & LEAF) {
        for (let i = 0; i < count; i++) {
          const e = PAGE_HEADER + i * ELEMENT_SIZE;
          const elFlags = page.readUInt32LE(e);
          const pos = page.readUInt32LE(e + 4);
          const ksize = page.readUInt32LE(e + 8);
          const vsize = page.readUInt32LE(e + 12);
          const k = slice(page, e + pos, ksize);
          const cmp = Buffer.compare(k, key);
          if (cmp === 0)
            return {
              value: slice(page, e + pos + ksize, vsize),
              bucket: (elFlags & BUCKET_LEAF) !== 0,
            };
          if (cmp > 0) return null;
        }
        return null;
      }
      if (!(flags & BRANCH) || node.kind === 'inline')
        throw new TrivyDbError('BD de Trivy no válida (página inesperada)');
      // Último elemento con clave <= la buscada (el primero si todas son mayores).
      let child: bigint | null = null;
      for (let i = 0; i < count; i++) {
        const e = PAGE_HEADER + i * ELEMENT_SIZE;
        const pos = page.readUInt32LE(e);
        const ksize = page.readUInt32LE(e + 4);
        if (i > 0 && Buffer.compare(slice(page, e + pos, ksize), key) > 0)
          break;
        child = page.readBigUInt64LE(e + 8);
      }
      if (child === null)
        throw new TrivyDbError('BD de Trivy no válida (rama vacía)');
      page = await this.page({ kind: 'page', pgid: child });
    }
    throw new TrivyDbError('BD de Trivy no válida (árbol demasiado profundo)');
  }

  private async page(node: Node): Promise<Buffer> {
    if (node.kind === 'inline') return node.page;
    const meta = this.m!;
    // Las páginas 0 y 1 son las meta; nada válido apunta más allá de la marca de agua.
    if (node.pgid < 2n || node.pgid >= meta.highWater)
      throw new TrivyDbError('BD de Trivy no válida (página fuera de rango)');
    const offset = node.pgid * BigInt(meta.pageSize);
    const head = await this.read(offset, meta.pageSize);
    const overflow = head.readUInt32LE(12);
    if (head.readBigUInt64LE(0) !== node.pgid || overflow > MAX_OVERFLOW)
      throw new TrivyDbError('BD de Trivy no válida (página corrupta)');
    return overflow
      ? this.read(offset, (overflow + 1) * meta.pageSize)
      : head;
  }

  private async read(offset: bigint, length: number): Promise<Buffer> {
    const buf = Buffer.alloc(length);
    const { bytesRead } = await this.fh.read(buf, 0, length, Number(offset));
    if (bytesRead !== length)
      throw new TrivyDbError('BD de Trivy truncada');
    return buf;
  }
}

/** Meta de BoltDB: magic, versión, tamaño de página, raíz, marca de agua, txid y checksum FNV-1a. */
function parseMeta(page: Buffer): Meta | null {
  if (page.length < PAGE_HEADER + 64) return null;
  if (!(page.readUInt16LE(8) & META)) return null;
  const m = page.subarray(PAGE_HEADER);
  if (m.readUInt32LE(0) !== BOLT_MAGIC || m.readUInt32LE(4) !== BOLT_VERSION)
    return null;
  if (m.readBigUInt64LE(56) !== fnv64a(m.subarray(0, 56))) return null;
  const pageSize = m.readUInt32LE(8);
  if (pageSize < 1024 || pageSize > 65_536 || pageSize & (pageSize - 1))
    return null;
  return {
    pageSize,
    root: m.readBigUInt64LE(16),
    highWater: m.readBigUInt64LE(40),
    txid: m.readBigUInt64LE(48),
  };
}

/** Valor de un bucket: `{ root, sequence }` y, si `root` es 0, su página inline detrás. */
function bucketRoot(value: Buffer): Node {
  if (value.length < BUCKET_HEADER)
    throw new TrivyDbError('BD de Trivy no válida (bucket)');
  const root = value.readBigUInt64LE(0);
  if (root !== 0n) return { kind: 'page', pgid: root };
  const page = value.subarray(BUCKET_HEADER);
  if (page.length < PAGE_HEADER || !(page.readUInt16LE(8) & LEAF))
    throw new TrivyDbError('BD de Trivy no válida (bucket inline)');
  return { kind: 'inline', page };
}

function slice(page: Buffer, start: number, length: number): Buffer {
  if (start < 0 || start + length > page.length)
    throw new TrivyDbError('BD de Trivy no válida (elemento fuera de la página)');
  return page.subarray(start, start + length);
}

const FNV_OFFSET = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;
const U64 = (1n << 64n) - 1n;

export function fnv64a(data: Buffer): bigint {
  let hash = FNV_OFFSET;
  for (const byte of data) hash = ((hash ^ BigInt(byte)) * FNV_PRIME) & U64;
  return hash;
}

const MAX_REFERENCES = 200;

/** JSON de trivy-db (`types.Vulnerability`) a lo que se muestra. Solo campos conocidos y acotados. */
export function parseVulnerability(raw: Buffer): VulnerabilityDetails {
  let v: Record<string, unknown>;
  try {
    v = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
  } catch {
    throw new TrivyDbError('Detalles del CVE ilegibles en la BD de Trivy');
  }
  const cvss: CvssScore[] = [];
  if (v.CVSS && typeof v.CVSS === 'object')
    for (const [source, value] of Object.entries(v.CVSS)) {
      if (!value || typeof value !== 'object') continue;
      const c = value as Record<string, unknown>;
      cvss.push({
        source: source.slice(0, 64),
        v2Score: num(c.V2Score),
        v2Vector: str(c.V2Vector, 256),
        v3Score: num(c.V3Score),
        v3Vector: str(c.V3Vector, 256),
        v40Score: num(c.V40Score),
        v40Vector: str(c.V40Vector, 512),
      });
    }
  return {
    title: str(v.Title, 500),
    description: str(v.Description, 20_000),
    severity: str(v.Severity, 16)?.toUpperCase() ?? null,
    cweIds: strings(v.CweIDs, 64, 32),
    cvss,
    references: strings(v.References, 1024, MAX_REFERENCES),
    publishedAt: str(v.PublishedDate, 64),
    lastModifiedAt: str(v.LastModifiedDate, 64),
  };
}

function str(value: unknown, max: number): string | null {
  return typeof value === 'string' && value ? value.slice(0, max) : null;
}

function num(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function strings(value: unknown, max: number, limit: number): string[] {
  return Array.isArray(value)
    ? value
        .filter((s): s is string => typeof s === 'string' && !!s)
        .slice(0, limit)
        .map((s) => s.slice(0, max))
    : [];
}
